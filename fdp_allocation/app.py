from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from sqlalchemy import and_
from sqlalchemy import text

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///fdp.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    name = db.Column(db.String(100))
    department = db.Column(db.String(100))
    selections = db.relationship('Selection', back_populates='user', lazy=True)
    completed_fdps = db.relationship('CompletedFDP', backref='user', lazy=True)  # For future
    previous_selections = db.relationship('PreviousSelection', backref='user', lazy=True) #for batches

class FDP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    faculty_in_charge = db.Column(db.String(100), nullable=False)
    total_seats = db.Column(db.Integer, nullable=False)
    available_seats = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(20), default='view')  # 'view' or 'allocate'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    description = db.Column(db.Text)
    selections = db.relationship('Selection', backref='fdp', lazy=True)
    completed_by = db.relationship('CompletedFDP', backref='fdp', lazy=True)  # For future
    previous_selections_list = db.relationship('PreviousSelection', backref='fdp', lazy=True)  #for batches

class Selection(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    fdp_id = db.Column(db.Integer, db.ForeignKey('fdp.id'), nullable=False)
    status = db.Column(db.String(20), default='selected')  # 'selected' or 'allocated'
    is_current = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='user_selections')  # Relationship to User.
    fdp = db.relationship('FDP', backref='fdp_selections')  # Relationship to FDP.

# Future Model (for "Completed FDPs" feature - add this)
class CompletedFDP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    fdp_id = db.Column(db.Integer, db.ForeignKey('fdp.id'), nullable=False)
    completed_at = db.Column(db.DateTime, default=datetime.utcnow)
     # Relationships (Important for easy access to related data)
    user = db.relationship('User', backref='completed_fdps_list') # Use a different name
    fdp = db.relationship('FDP', backref='completed_fdps_list')

class PreviousSelection(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    fdp_id = db.Column(db.Integer, db.ForeignKey('fdp.id'), nullable=False)
    status = db.Column(db.String(20), default='selected') # Keep status for consistency
    batch_timestamp = db.Column(db.DateTime, default=datetime.utcnow) # Timestamp for the batch
    # Relationships (Important for easy access to related data)
    user = db.relationship('User', backref='previous_user_selections') # Use a different name
    fdp = db.relationship('FDP', backref='previous_user_fdps')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Common Routes (Login, Signup, Logout)
@app.route('/')
def login():
    return render_template('login.html')

@app.route('/auth', methods=['POST'])
def auth():
    data = request.form
    user = User.query.filter_by(username=data['username']).first()

    if user and check_password_hash(user.password, data['password']):
        login_user(user)
        if user.is_admin:
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('faculty_dashboard'))
    else:
        flash('Invalid credentials', 'error')
        return redirect(url_for('login'))

@app.route('/signup', methods=['POST'])
def signup():
    data = request.form
    existing_user = User.query.filter_by(username=data['username']).first()
    if existing_user:
        flash('Username already exists', 'error')
        return redirect(url_for('login'))
    else:
        hashed_password = generate_password_hash(data['password'])
        new_user = User(username=data['username'], password=hashed_password, name=data['name'], department=data['department'])
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully, please login', 'success')
        return redirect(url_for('login'))

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
    else:
        fdps = FDP.query.all()
        faculty_count = User.query.filter_by(is_admin=False).count()
        active_allocations = Selection.query.filter_by(is_current=True).count()  # Needs review after allocation
        total_available_seats = sum(fdp.available_seats for fdp in fdps)
        recent_activities = [{'icon': '📝', 'message': f'New FDP "{fdp.name}" added', 'time': fdp.created_at.strftime('%Y-%m-%d %H:%M')} for fdp in FDP.query.order_by(FDP.created_at.desc()).limit(5)]
        faculty_list = [{'id': f.id, 'name': f.name, 'department': f.department, 'username': f.username, 'allocated_fdps': [a.fdp for a in Selection.query.filter_by(user_id=f.id, is_current=True, status='allocated').all()]} for f in User.query.filter_by(is_admin=False).all()] # Pass list of FDP objects

        allocations_data_for_table = get_formatted_allocations() # Helper function for allocations table data

        return render_template('admin/dashboard.html', fdps=fdps, faculty_count=faculty_count, active_allocations=active_allocations,
                               total_available_seats=total_available_seats, recent_activities=recent_activities, faculty_list=faculty_list, allocations=allocations_data_for_table)

@app.route('/admin/fdp/add', methods=['POST'])
@login_required
def add_fdp():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    else:
        data = request.form
        if not all(k in data for k in ('name', 'faculty_in_charge', 'total_seats')):
            flash('All fields are required.', 'error')
            return redirect(url_for('admin_dashboard'))
        else:
            try:
                total_seats = int(data['total_seats'])
                if total_seats <= 0:
                    flash('Seats must be positive.', 'error')
                    return redirect(url_for('admin_dashboard'))
                else:
                    new_fdp = FDP(name=data['name'], faculty_in_charge=data['faculty_in_charge'], total_seats=total_seats, available_seats=total_seats, description=data.get('description', ''))
                    db.session.add(new_fdp)
                    db.session.commit()
                    flash('FDP added successfully', 'success')
                    return redirect(url_for('admin_dashboard'))
            except ValueError:
                flash('Invalid seats value.', 'error')
                return redirect(url_for('admin_dashboard'))

@app.route('/admin/fdp/get/<int:fdp_id>')
@login_required
def get_fdp(fdp_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    else:
        fdp = FDP.query.get_or_404(fdp_id)
        fdp_data = {'id': fdp.id, 'name': fdp.name, 'faculty_in_charge': fdp.faculty_in_charge, 'total_seats': fdp.total_seats, 'description': fdp.description}
        return jsonify(fdp_data)

@app.route('/admin/fdp/edit/<int:fdp_id>', methods=['POST'])
@login_required
def edit_fdp(fdp_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    else:
        fdp = FDP.query.get_or_404(fdp_id)
        data = request.form
        if not all(k in data for k in ('name', 'faculty_in_charge', 'total_seats')):
            flash('All fields required to edit.', 'error')
            return jsonify({'success': False, 'message': 'All fields are required.'})  # Return JSON on error
        else:
            try:
                total_seats = int(data['total_seats'])
                if total_seats <= 0:
                    flash('Seats must be positive.', 'error')
                    return jsonify({'success': False, 'message': 'Seats must be positive.'})  # Return JSON on error
                else:
                    fdp.name = data['name']
                    fdp.faculty_in_charge = data['faculty_in_charge']
                    fdp.total_seats = total_seats
                    fdp.description = data.get('description', '')

                    db.session.commit()
                    # Return a JSON response with updated FDP data to update the UI
                    return jsonify({'success': True, 'message': 'FDP updated successfully', 'fdp': {
                        'id': fdp.id,
                        'name': fdp.name,
                        'faculty_in_charge': fdp.faculty_in_charge,
                        'total_seats': fdp.total_seats,
                        'available_seats': fdp.available_seats,
                        'status': fdp.status,
                        'created_at': fdp.created_at.strftime('%Y-%m-%d')  # Format date for consistency
                    }})
            except ValueError:
                flash('Invalid seats value.', 'error')
                return jsonify({'success': False, 'message': 'Invalid seats value.'}) # Return JSON on error

@app.route('/admin/toggle_fdp/<int:fdp_id>')
@login_required
def toggle_fdp(fdp_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    else:
        fdp = FDP.query.get_or_404(fdp_id)
        old_status = fdp.status  # Store old status *before* changing it
        if fdp.status == 'view':
            fdp.status = 'allocate'
        else:
            fdp.status = 'view'
        new_status = fdp.status  # Store the new status
        db.session.commit()
        return jsonify({'success': True, 'message': f'FDP status toggled to {new_status.title()}', 'new_status': new_status, 'old_status': old_status}) # Return JSON

@app.route('/admin/fdp/delete/<int:fdp_id>', methods=['POST'])
@login_required
def delete_fdp(fdp_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    else:
        fdp = FDP.query.get_or_404(fdp_id)
        active_allocations = Selection.query.filter_by(fdp_id=fdp_id, is_current=True).first()
        if active_allocations:
            flash('Cannot delete FDP with active allocations.', 'error')
            return redirect(url_for('admin_dashboard'))
        else:
            db.session.delete(fdp)
            db.session.commit()
            flash('FDP deleted successfully', 'success')
            return redirect(url_for('admin_dashboard'))

@app.route('/admin/allocations')
@login_required
def view_allocations(): # Reusing formatted allocations logic as a function
    return jsonify(get_formatted_allocations())


def get_formatted_allocations(): # Helper function to get formatted allocations data - reused in admin dashboard and allocations view route.
    allocations_query = db.session.query(Selection, User, FDP).join(User, Selection.user_id == User.id).join(FDP, Selection.fdp_id == FDP.id).filter(Selection.is_current == True, Selection.status == 'allocated').all()
    formatted_allocations = [{'id': a.Selection.id, 'faculty_name': a.User.name, 'fdp_name': a.FDP.name, 'date': a.Selection.created_at.strftime('%Y-%m-%d'), 'status': 'Active' if a.Selection.is_current else 'Completed'} for a in allocations_query]
    return formatted_allocations


@app.route('/admin/reports/utilization')
@login_required
def fdp_utilization():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    else:
        fdps = FDP.query.all()
        utilization_data = [{'name': fdp.name, 'total': fdp.total_seats, 'allocated': fdp.total_seats - fdp.available_seats, 'available': fdp.available_seats} for fdp in fdps]
        return jsonify(utilization_data)

# Faculty Routes
@app.route('/faculty/dashboard')
@login_required
def faculty_dashboard():
    if not current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    else:
        available_fdps = FDP.query.filter(and_(FDP.status == 'allocate', FDP.available_seats > 0)).all()
        selected_fdps = Selection.query.filter_by(user_id=current_user.id, is_current=True, status='selected').all() #Fetch selection
        allocated_fdps = Selection.query.filter_by(user_id=current_user.id, status='allocated').all() #fetch allocated

        # --- New Logic for Limited Availability Cases ---
        available_fdp_count = len(available_fdps)
        total_fdp_count = FDP.query.count() # Get total count of FDPs (regardless of status)
        message = None  # Initialize a message variable

        if available_fdp_count == 0:
            message = "No FDPs are currently available for selection. Please check back later."
        elif available_fdp_count == 1:
            message = "Only one FDP is currently available.  Select it if desired." # Could automatically select it - see below
        elif total_fdp_count == 3:
            message = "There are only three FDPs in total.  These will be directly allocated."

        return render_template('faculty/dashboard.html', available_fdps=available_fdps,
                              selected_fdps=selected_fdps, allocated_fdps=allocated_fdps,
                              message=message) # Pass the message

@app.route('/faculty/select_fdp', methods=['POST'])
@login_required
def select_fdp():
    print("--- select_fdp route accessed ---")
    print("current_user:", current_user)
    print("current_user.is_authenticated:", current_user.is_authenticated)
    print("current_user.is_admin:", current_user.is_admin if hasattr(current_user, 'is_admin') else "AttributeError: 'is_admin' not found")
    print("current_user.id", current_user.id if hasattr(current_user, 'id') else "AttributeError: 'id' not found")
    print("current_user.username", current_user.username if hasattr(current_user, 'username') else "AttributeError: 'username' not found" )

    if current_user.is_admin:
        print("--- Inside is_admin block (should NOT happen for faculty) ---")  # Debug print
        return jsonify({'error': 'Unauthorized'}), 403
    else:
        print("--- Inside else block (expected for faculty) ---")  # Debug print
        fdp_ids = request.form.getlist('fdp_ids[]')
        print("fdp_ids:", fdp_ids)

        if not fdp_ids:
            flash('Please select at least one FDP.', 'error')
            return jsonify({'success': False, 'message': 'Please select at least one FDP'})

        if len(fdp_ids) > 5:
            flash('You can select a maximum of 5 FDPs.', 'error')
            return jsonify({'success': False, 'message': 'You can select a maximum of 5 FDPs'})

        Selection.query.filter_by(user_id=current_user.id, is_current=True).delete()
        for fdp_id in fdp_ids[:5]:
            selection = Selection(user_id=current_user.id, fdp_id=int(fdp_id))
            db.session.add(selection)
        db.session.commit()
        flash('Your FDP selections submitted successfully!', 'success') # Changed text slightly for easier ID
        return jsonify({'success': True, 'message': 'Your FDP selections submitted successfully!'})



@app.route('/admin/start_new_batch', methods=['POST'])
@login_required
def start_new_batch():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    # Get all current selections
    current_selections = Selection.query.filter_by(is_current=True).all()

    # Create PreviousSelection records from current selections
    for selection in current_selections:
        prev_selection = PreviousSelection(
            user_id=selection.user_id,
            fdp_id=selection.fdp_id,
            status=selection.status,  # Keep the status (e.g., 'selected', 'allocated')
            # batch_timestamp is automatically set by the default value
        )
        db.session.add(prev_selection)

    # Delete *all* current selections (or set is_current=False)
    # We're deleting to make selection process simple. Setting
    # is_current = False might be good if we want to show old
    # selection data in the UI, but is NOT a replacement for
    # a full-fledged "PreviousSelection" table.

    Selection.query.filter_by(is_current=True).delete() # Delete is simpler

    db.session.commit()
    flash('New batch started! Previous selections moved to history.', 'success')
    return jsonify({'success': True, 'message': 'New batch started!'})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        admin_user = User.query.filter_by(is_admin=True).first()
        if not admin_user:
            default_admin = User(username='admin', password=generate_password_hash('adminpassword'), is_admin=True, name='Admin User')
            db.session.add(default_admin)
            db.session.commit()
            print("Default admin user created: username='admin', password='adminpassword' (Change this ASAP!)")
    app.run(debug=True)