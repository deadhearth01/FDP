from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from sqlalchemy import and_, func, text
from sqlalchemy.exc import OperationalError
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import json
import threading

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///fdp.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# SMTP Configuration
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USERNAME = 'dgadamse2@gitam.in'
SMTP_PASSWORD = 'emroquqcpklfnpoj'
FROM_EMAIL = 'dgadamse2@gitam.in'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Models (unchanged)
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    name = db.Column(db.String(100))
    department = db.Column(db.String(100))
    selections = db.relationship('Selection', back_populates='user', lazy=True)
    completed_fdps = db.relationship('CompletedFDP', back_populates='user', lazy=True)
    previous_selections = db.relationship('PreviousSelection', back_populates='user', lazy=True)
    email_history = db.relationship('EmailHistory', backref='user', lazy=True)

class FDP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    faculty_in_charge = db.Column(db.String(100), nullable=False)
    total_seats = db.Column(db.Integer, nullable=False)
    available_seats = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(20), default='view')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    description = db.Column(db.Text)
    version_id = db.Column(db.Integer, nullable=False, default=0)
    start_date = db.Column(db.DateTime, nullable=True)
    end_date = db.Column(db.DateTime, nullable=True)
    resource_person = db.Column(db.Text, nullable=True)
    selections = db.relationship('Selection', back_populates='fdp', lazy=True)
    completed_fdps = db.relationship('CompletedFDP', back_populates='fdp', lazy=True)
    previous_selections = db.relationship('PreviousSelection', back_populates='fdp', lazy=True)

    __mapper_args__ = {'version_id_col': version_id}

class Selection(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    fdp_id = db.Column(db.Integer, db.ForeignKey('fdp.id'), nullable=False)
    status = db.Column(db.String(20), default='selected')
    is_current = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', back_populates='selections')
    fdp = db.relationship('FDP', back_populates='selections')

class CompletedFDP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    fdp_id = db.Column(db.Integer, db.ForeignKey('fdp.id'), nullable=False)
    completed_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', back_populates='completed_fdps')
    fdp = db.relationship('FDP', back_populates='completed_fdps')

class PreviousSelection(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    fdp_id = db.Column(db.Integer, db.ForeignKey('fdp.id'), nullable=False)
    status = db.Column(db.String(20), default='selected')
    batch_timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', back_populates='previous_selections')
    fdp = db.relationship('FDP', back_populates='previous_selections')

class EmailHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    email_type = db.Column(db.String(50), nullable=False)
    sent_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Email sending function using Gmail SMTP
def send_email(user, subject, content, is_allocation=False, fdp=None):
    msg = MIMEMultipart()
    msg['From'] = FROM_EMAIL
    msg['To'] = user.email
    msg['Subject'] = subject
    msg.attach(MIMEText(content, 'plain'))

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.sendmail(FROM_EMAIL, [user.email], msg.as_string())
        print(f"Email sent to {user.email} with subject: {subject}")

        # Log to EmailHistory
        email_type = "Allocation" if is_allocation else "Login"
        email_entry = EmailHistory(user_id=user.id, email_type=email_type)
        db.session.add(email_entry)
        db.session.commit()
    except Exception as e:
        print(f"Failed to send email to {user.email}: {e}")
        db.session.rollback()
        raise

def send_email_async(user, subject, content, is_allocation=False, fdp=None):
    thread = threading.Thread(target=send_email, args=(user, subject, content, is_allocation, fdp))
    thread.start()
    print(f"Started email thread for {subject} to {user.email}")

# Migration function
def migrate_database():
    try:
        db.session.execute(text("SELECT version_id FROM fdp LIMIT 1"))
    except OperationalError:
        db.session.execute(text("ALTER TABLE fdp ADD COLUMN version_id INTEGER NOT NULL DEFAULT 0"))
        db.session.commit()
        print("Added version_id column to fdp table.")

    try:
        db.session.execute(text("SELECT start_date FROM fdp LIMIT 1"))
    except OperationalError:
        db.session.execute(text("ALTER TABLE fdp ADD COLUMN start_date DATETIME"))
        db.session.commit()
        print("Added start_date column to fdp table.")

    try:
        db.session.execute(text("SELECT end_date FROM fdp LIMIT 1"))
    except OperationalError:
        db.session.execute(text("ALTER TABLE fdp ADD COLUMN end_date DATETIME"))
        db.session.commit()
        print("Added end_date column to fdp table.")

    try:
        db.session.execute(text("SELECT resource_person FROM fdp LIMIT 1"))
    except OperationalError:
        db.session.execute(text("ALTER TABLE fdp ADD COLUMN resource_person TEXT"))
        db.session.commit()
        print("Added resource_person column to fdp table.")

    try:
        db.session.execute(text("SELECT email FROM user LIMIT 1"))
    except OperationalError:
        db.session.execute(text("ALTER TABLE user ADD COLUMN email VARCHAR(120) UNIQUE NOT NULL"))
        db.session.commit()
        print("Added email column to user table.")

# Common Routes
@app.route('/')
def login():
    return render_template('login.html')

@app.route('/auth', methods=['POST'])
def auth():
    data = request.form
    user = User.query.filter_by(username=data['username']).first()
    if user and check_password_hash(user.password, data['password']):
        login_user(user)
        subject = "Welcome Back to FDP Allocation System"
        content = f"""
        Hello {user.name},
        You have successfully logged into the FDP Allocation System at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}.
        We’re glad to see you back!
        Best regards,
        The FDP Allocation Team
        """
        send_email_async(user, subject, content)
        return redirect(url_for('admin_dashboard') if user.is_admin else url_for('faculty_dashboard'))
    flash('Invalid credentials', 'error')
    return redirect(url_for('login'))

@app.route('/signup', methods=['POST'])
def signup():
    data = request.form
    existing_user = User.query.filter_by(username=data['username']).first()
    existing_email = User.query.filter_by(email=data['email']).first()
    
    if existing_user:
        flash('Username already exists', 'error')
        return redirect(url_for('login'))
    if existing_email:
        flash('Email address already registered', 'error')
        return redirect(url_for('login'))
    
    new_user = User(
        username=data['username'],
        password=generate_password_hash(data['password']),
        email=data['email'],
        name=data['name'],
        department=data['department']
    )
    db.session.add(new_user)
    db.session.commit()
    login_user(new_user)
    subject = "Welcome to FDP Allocation System"
    content = f"""
    Hello {new_user.name},
    Your account has been successfully created at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}.
    Welcome to the FDP Allocation System!
    Best regards,
    The FDP Allocation Team
    """
    send_email_async(new_user, subject, content)
    flash('Account created successfully! Welcome to the FDP Allocation System.', 'success')
    return redirect(url_for('faculty_dashboard'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Admin Routes
@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        return redirect(url_for('faculty_dashboard'))
    fdps = FDP.query.all()
    faculty_count = User.query.filter_by(is_admin=False).count()
    active_allocations = Selection.query.filter_by(is_current=True, status='allocated').count()
    total_available_seats = sum(fdp.available_seats for fdp in fdps)
    recent_activities = [
        {'icon': '📝', 'message': f'New FDP "{fdp.name}" added', 'time': fdp.created_at.strftime('%Y-%m-%d %H:%M')}
        for fdp in FDP.query.order_by(FDP.created_at.desc()).limit(5)
    ]
    faculty_list = [
        {
            'id': f.id,
            'name': f.name,
            'department': f.department,
            'username': f.username,
            'email': f.email,
            'allocated_fdps': [
                {
                    'id': s.fdp.id,
                    'name': s.fdp.name,
                    'faculty_in_charge': s.fdp.faculty_in_charge,
                    'total_seats': s.fdp.total_seats,
                    'available_seats': s.fdp.available_seats,
                    'start_date': s.fdp.start_date.strftime('%Y-%m-%d') if s.fdp.start_date else 'N/A',
                    'end_date': s.fdp.end_date.strftime('%Y-%m-%d') if s.fdp.end_date else 'N/A',
                    'resource_person': json.loads(s.fdp.resource_person) if s.fdp.resource_person else []
                }
                for s in Selection.query.filter_by(user_id=f.id, is_current=True, status='allocated').all()
            ],
            'email_history': [
                {
                    'email_type': eh.email_type,
                    'sent_at': eh.sent_at.strftime('%Y-%m-%d %H:%M')
                }
                for eh in f.email_history
            ]
        }
        for f in User.query.filter_by(is_admin=False).all()
    ]
    allocations = get_formatted_allocations()
    return render_template(
        'admin/dashboard.html',
        fdps=fdps,
        faculty_count=faculty_count,
        active_allocations=active_allocations,
        total_available_seats=total_available_seats,
        recent_activities=recent_activities,
        faculty_list=faculty_list,
        allocations=allocations
    )

@app.route('/admin/fdp/add', methods=['POST'])
@login_required
def add_fdp():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    data = request.form
    required_fields = ['name', 'faculty_in_charge', 'total_seats']
    if not all(k in data for k in required_fields):
        flash('All required fields must be filled.', 'error')
        return redirect(url_for('admin_dashboard'))
    try:
        total_seats = int(data['total_seats'])
        if total_seats <= 0:
            flash('Seats must be a positive number.', 'error')
            return redirect(url_for('admin_dashboard'))
        start_date = datetime.strptime(data['start_date'], '%Y-%m-%d') if 'start_date' in data and data['start_date'] else None
        end_date = datetime.strptime(data['end_date'], '%Y-%m-%d') if 'end_date' in data and data['end_date'] else None
        resource_person = json.dumps(data['resource_person'].split(',')) if 'resource_person' in data and data['resource_person'] else None
        new_fdp = FDP(
            name=data['name'],
            faculty_in_charge=data['faculty_in_charge'],
            total_seats=total_seats,
            available_seats=total_seats,
            description=data.get('description', ''),
            start_date=start_date,
            end_date=end_date,
            resource_person=resource_person
        )
        db.session.add(new_fdp)
        db.session.commit()
        flash('FDP added successfully', 'success')
    except ValueError as e:
        flash('Invalid input data. Ensure dates are in YYYY-MM-DD format and seats are numeric.', 'error')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/fdp/get/<int:fdp_id>')
@login_required
def get_fdp(fdp_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    fdp = FDP.query.get_or_404(fdp_id)
    return jsonify({
        'id': fdp.id,
        'name': fdp.name,
        'faculty_in_charge': fdp.faculty_in_charge,
        'total_seats': fdp.total_seats,
        'description': fdp.description,
        'start_date': fdp.start_date.strftime('%Y-%m-%d') if fdp.start_date else '',
        'end_date': fdp.end_date.strftime('%Y-%m-%d') if fdp.end_date else '',
        'resource_person': json.loads(fdp.resource_person) if fdp.resource_person else []
    })

@app.route('/admin/fdp/edit/<int:fdp_id>', methods=['POST'])
@login_required
def edit_fdp(fdp_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    fdp = FDP.query.get_or_404(fdp_id)
    data = request.form
    required_fields = ['name', 'faculty_in_charge', 'total_seats']
    if not all(k in data for k in required_fields):
        return jsonify({'success': False, 'message': 'All required fields must be filled.'})
    try:
        total_seats = int(data['total_seats'])
        if total_seats <= 0:
            return jsonify({'success': False, 'message': 'Seats must be a positive number.'})
        start_date = datetime.strptime(data['start_date'], '%Y-%m-%d') if 'start_date' in data and data['start_date'] else None
        end_date = datetime.strptime(data['end_date'], '%Y-%m-%d') if 'end_date' in data and data['end_date'] else None
        resource_person = json.dumps(data['resource_person'].split(',')) if 'resource_person' in data and data['resource_person'] else None
        fdp.name = data['name']
        fdp.faculty_in_charge = data['faculty_in_charge']
        fdp.total_seats = total_seats
        fdp.description = data.get('description', '')
        fdp.start_date = start_date
        fdp.end_date = end_date
        fdp.resource_person = resource_person
        db.session.commit()
        return jsonify({
            'success': True,
            'message': 'FDP updated successfully',
            'fdp': {
                'id': fdp.id,
                'name': fdp.name,
                'faculty_in_charge': fdp.faculty_in_charge,
                'total_seats': fdp.total_seats,
                'available_seats': fdp.available_seats,
                'status': fdp.status,
                'created_at': fdp.created_at.strftime('%Y-%m-%d'),
                'start_date': fdp.start_date.strftime('%Y-%m-%d') if fdp.start_date else '',
                'end_date': fdp.end_date.strftime('%Y-%m-%d') if fdp.end_date else '',
                'resource_person': json.loads(fdp.resource_person) if fdp.resource_person else []
            }
        })
    except ValueError:
        return jsonify({'success': False, 'message': 'Invalid input data. Ensure dates are in YYYY-MM-DD format.'})

@app.route('/admin/toggle_fdp/<int:fdp_id>')
@login_required
def toggle_fdp(fdp_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    fdp = FDP.query.get_or_404(fdp_id)
    old_status = fdp.status
    fdp.status = 'allocate' if fdp.status == 'view' else 'view'
    new_status = fdp.status
    db.session.commit()
    return jsonify({
        'success': True,
        'message': f'FDP status toggled to {new_status.title()}',
        'new_status': new_status,
        'old_status': old_status
    })

@app.route('/admin/fdp/delete/<int:fdp_id>', methods=['POST'])
@login_required
def delete_fdp(fdp_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    fdp = FDP.query.get_or_404(fdp_id)
    if Selection.query.filter_by(fdp_id=fdp_id, is_current=True).first():
        flash('Cannot delete FDP with active allocations.', 'error')
    else:
        db.session.delete(fdp)
        db.session.commit()
        flash('FDP deleted successfully', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/allocations')
@login_required
def view_allocations():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    return jsonify(get_formatted_allocations())

def get_formatted_allocations():
    allocations = db.session.query(Selection, User, FDP)\
        .join(User, Selection.user_id == User.id)\
        .join(FDP, Selection.fdp_id == FDP.id)\
        .filter(Selection.is_current == True, Selection.status == 'allocated').all()
    return [
        {
            'id': a.Selection.id,
            'faculty_name': a.User.name,
            'fdp_name': a.FDP.name,
            'date': a.Selection.created_at.strftime('%Y-%m-%d'),
            'status': 'Active' if a.Selection.is_current else 'Completed',
            'start_date': a.FDP.start_date.strftime('%Y-%m-%d') if a.FDP.start_date else 'N/A',
            'end_date': a.FDP.end_date.strftime('%Y-%m-%d') if a.FDP.end_date else 'N/A',
            'resource_person': json.loads(a.FDP.resource_person) if a.FDP.resource_person else []
        }
        for a in allocations
    ]

@app.route('/admin/reports/utilization')
@login_required
def get_utilization_report():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    fdps = FDP.query.all()
    utilization_data = [
        {'name': fdp.name, 'allocated': (fdp.total_seats - fdp.available_seats), 'available': fdp.available_seats}
        for fdp in fdps
    ]
    return jsonify(utilization_data)

@app.route('/admin/reports/department_participation')
@login_required
def get_department_participation():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    departments = db.session.query(User.department, func.count(Selection.id))\
        .outerjoin(Selection, and_(User.id == Selection.user_id, Selection.status == 'allocated'))\
        .group_by(User.department).all()
    participation_data = [{'department': dept[0], 'participation': dept[1]} for dept in departments]
    return jsonify(participation_data)

@app.route('/admin/previous_allocations')
@login_required
def previous_allocations():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    previous_selections = PreviousSelection.query.all()
    allocations_data = [
        {
            'id': ps.id,
            'faculty_name': ps.user.name,
            'fdp_name': ps.fdp.name,
            'batch_timestamp': ps.batch_timestamp.strftime('%Y-%m-%d %H:%M')
        }
        for ps in previous_selections
    ]
    return jsonify(allocations_data)

@app.route('/admin/start_new_batch', methods=['POST'])
@login_required
def start_new_batch():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    current_selections = Selection.query.filter_by(is_current=True).all()
    for selection in current_selections:
        prev_selection = PreviousSelection(
            user_id=selection.user_id,
            fdp_id=selection.fdp_id,
            status=selection.status,
            batch_timestamp=datetime.utcnow()
        )
        db.session.add(prev_selection)
    Selection.query.filter_by(is_current=True).delete()
    db.session.commit()
    flash('New batch started! Previous selections moved to history.', 'success')
    return jsonify({'success': True, 'message': 'New batch started!'})

# Faculty Routes
@app.route('/faculty/dashboard')
@login_required
def faculty_dashboard():
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    completed_fdp_ids = [cf.fdp_id for cf in current_user.completed_fdps]
    active_selections = [s.fdp_id for s in Selection.query.filter_by(user_id=current_user.id, is_current=True).all()]
    previous_selections = [ps.fdp_id for ps in PreviousSelection.query.filter_by(user_id=current_user.id).all()]
    previously_selected_fdp_ids = set(completed_fdp_ids + active_selections + previous_selections)

    available_fdps = FDP.query.filter(
        and_(FDP.status == 'allocate', FDP.available_seats > 0, ~FDP.id.in_(completed_fdp_ids))
    ).all()
    selected_fdps = Selection.query.filter_by(user_id=current_user.id, is_current=True, status='selected').all()
    allocated_fdps = Selection.query.filter_by(user_id=current_user.id, is_current=True, status='allocated').all()

    total_fdp_count = FDP.query.count()
    available_fdp_count = len(available_fdps)
    notification = None

    if total_fdp_count == 3:
        Selection.query.filter_by(user_id=current_user.id, is_current=True).delete()
        allocated_fdps = []
        for fdp in FDP.query.limit(3).all():
            if fdp.available_seats > 0:
                selection = Selection(user_id=current_user.id, fdp_id=fdp.id, status='allocated', is_current=True)
                fdp.available_seats -= 1
                fdp.version_id += 1
                db.session.add(selection)
                allocated_fdps.append(selection)
                subject = "FDP Allocation Confirmation"
                content = f"""
                Hello {current_user.name},
                Congratulations! You have been allocated the following FDP:
                - FDP Name: {fdp.name}
                - Faculty in Charge: {fdp.faculty_in_charge}
                - Start Date: {fdp.start_date.strftime('%Y-%m-%d') if fdp.start_date else 'N/A'}
                - End Date: {fdp.end_date.strftime('%Y-%m-%d') if fdp.end_date else 'N/A'}
                - Resource Person: {', '.join(json.loads(fdp.resource_person)) if fdp.resource_person else 'N/A'}
                - Allocation Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                Best regards,
                The FDP Allocation Team
                """
                send_email_async(current_user, subject, content, is_allocation=True, fdp=fdp)
        db.session.commit()
        notification = "Only three FDPs exist. They have been directly allocated to you."
    elif available_fdp_count == 0:
        notification = "No FDPs are currently available. Please wait for the next batch."
    elif available_fdp_count == 1:
        notification = "Only one FDP is available. Please select additional FDPs when more become available."

    return render_template(
        'faculty/dashboard.html',
        available_fdps=available_fdps,
        selected_fdps=selected_fdps,
        allocated_fdps=allocated_fdps,
        notification=notification,
        previously_selected_fdp_ids=list(previously_selected_fdp_ids)  # Pass the list to the template
    )

@app.route('/faculty/select_fdp', methods=['POST'])
@login_required
def select_fdp():
    if current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    # Get selected FDP IDs, but limit processing to a maximum of 3
    fdp_ids = request.form.getlist('fdp_ids[]')
    if not fdp_ids:
        return jsonify({'success': False, 'message': 'Please select at least one FDP'})

    # Limit the number of FDPs processed to 3 (or fewer if fewer are selected)
    max_fdps = min(3, len(fdp_ids))  # Ensure we only process up to 3 FDPs
    if len(fdp_ids) > 5:
        return jsonify({'success': False, 'message': 'You can select a maximum of 5 FDPs, but only 3 will be allocated'})

    completed_fdp_ids = [cf.fdp_id for cf in current_user.completed_fdps]
    active_selections = [s.fdp_id for s in Selection.query.filter_by(user_id=current_user.id, is_current=True).all()]
    previous_selections = [ps.fdp_id for ps in PreviousSelection.query.filter_by(user_id=current_user.id).all()]

    # Combine all previously selected/allocated FDP IDs to prevent reselection
    previously_selected_fdp_ids = set(completed_fdp_ids + active_selections + previous_selections)

    Selection.query.filter_by(user_id=current_user.id, is_current=True).delete()
    allocated_fdps = []
    conflicted = False

    # Only process up to 3 valid, non-previously-selected FDPs
    for fdp_id in fdp_ids[:max_fdps]:
        fdp_id = int(fdp_id)
        fdp = FDP.query.filter_by(id=fdp_id).first()
        if not fdp:
            conflicted = True
            continue

        # Check if this FDP was previously selected or allocated by this user
        if fdp_id in previously_selected_fdp_ids:
            conflicted = True
            continue

        if fdp.available_seats > 0 and fdp.id not in completed_fdp_ids:
            try:
                # Only decrease seats and allocate if we're within the 3-FDP limit and FDP is not previously selected
                fdp.available_seats -= 1
                fdp.version_id += 1
                selection = Selection(user_id=current_user.id, fdp_id=fdp.id, status='allocated', is_current=True)
                db.session.add(selection)
                allocated_fdps.append(selection)

                subject = "FDP Allocation Confirmation"
                content = f"""
                Hello {current_user.name},
                Congratulations! You have been allocated the following FDP:
                - FDP Name: {fdp.name}
                - Faculty in Charge: {fdp.faculty_in_charge}
                - Start Date: {fdp.start_date.strftime('%Y-%m-%d') if fdp.start_date else 'N/A'}
                - End Date: {fdp.end_date.strftime('%Y-%m-%d') if fdp.end_date else 'N/A'}
                - Resource Person: {', '.join(json.loads(fdp.resource_person)) if fdp.resource_person else 'N/A'}
                - Allocation Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                Best regards,
                The FDP Allocation Team
                """
                send_email_async(current_user, subject, content, is_allocation=True, fdp=fdp)
                db.session.commit()
            except:
                db.session.rollback()
                conflicted = True
                break
        else:
            conflicted = True

    if conflicted:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': 'One or more selected FDPs are no longer available, previously selected, or invalid. Please reselect.',
            'needs_reselection': True,
            'allocated': [s.fdp.name for s in allocated_fdps]
        })

    if len(allocated_fdps) == 0:
        return jsonify({
            'success': False,
            'message': 'No FDPs available or valid for allocation. Please wait for the next batch.',
            'needs_reselection': False
        })
    else:
        flash('Your FDP selections submitted and allocated successfully!', 'success')
        return jsonify({
            'success': True,
            'message': 'Your FDP selections submitted and allocated successfully!',
            'allocated': [s.fdp.name for s in allocated_fdps]
        })
    
@app.route('/faculty/fdp/get/<int:fdp_id>')
@login_required
def get_fdp_details(fdp_id):
    fdp = FDP.query.get_or_404(fdp_id)
    return jsonify({
        'name': fdp.name,
        'faculty_in_charge': fdp.faculty_in_charge,
        'description': fdp.description,
        'start_date': fdp.start_date.strftime('%Y-%m-%d') if fdp.start_date else None,
        'end_date': fdp.end_date.strftime('%Y-%m-%d') if fdp.end_date else None,
        'resource_person': json.loads(fdp.resource_person) if fdp.resource_person else [],
        'total_seats': fdp.total_seats,
        'available_seats': fdp.available_seats,
        'status': fdp.status
    })

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        migrate_database()
        if not User.query.filter_by(is_admin=True).first():
            default_admin = User(
                username='admin',
                password=generate_password_hash('adminpassword'),
                email='admin@example.com',
                is_admin=True,
                name='Admin User'
            )
            db.session.add(default_admin)
            db.session.commit()
            print("Default admin user created: username='admin', password='adminpassword' (Change this ASAP!)")
    
    # Change this line
    app.run(host='0.0.0.0', port=8080, debug=True)
