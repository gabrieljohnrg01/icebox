# app.py - Flask Startup Incubator Management System
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import os
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///incubator.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

db = SQLAlchemy(app)

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# ==================== DATABASE MODELS ====================

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100), nullable=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    contact_number = db.Column(db.String(20), nullable=True)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'super_admin', 'admin', 'incubatee'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    
    
    # Relationships
    startups = db.relationship('Startup', backref='owner', lazy=True, foreign_keys='Startup.owner_id')
    memberships = db.relationship('StartupMember', backref='user', lazy=True)
    progress_reports = db.relationship('ProgressReport', backref='submitted_by_user', lazy=True)

class Startup(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    logo = db.Column(db.String(200), nullable=True)
    industry = db.Column(db.String(100), nullable=True)
    stage = db.Column(db.String(50), default='ideation')
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    email = db.Column(db.String(120), nullable=True)
    contact_number = db.Column(db.String(20), nullable=True)
    
    # Relationships
    members = db.relationship('StartupMember', backref='startup', lazy=True, cascade='all, delete-orphan')
    milestones = db.relationship('Milestone', backref='startup', lazy=True, cascade='all, delete-orphan')
    progress_reports = db.relationship('ProgressReport', backref='startup', lazy=True, cascade='all, delete-orphan')

class StartupMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    startup_id = db.Column(db.Integer, db.ForeignKey('startup.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    role = db.Column(db.String(100), nullable=True)  # CEO, CTO, etc.
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)

class Milestone(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    startup_id = db.Column(db.Integer, db.ForeignKey('startup.id'), nullable=False)
    milestone_progress = db.Column(db.Integer, nullable=True)
    status = db.Column(db.String(20), default='not')  #not-yet, pending, completed

class Temporaryfile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

class Deliverable(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    milestonegroup_id = db.Column(db.Integer, db.ForeignKey('milestone.id'), nullable=False)    
    temp_file_id = db.Column(db.Integer, db.ForeignKey('temporaryfile.id'), nullable=True)
    deliverable_name = db.Column(db.String(200), nullable=False)
    upload_file = db.Column(db.String(200), nullable=False)
    due_date = db.Column(db.Date, nullable=True)
    requirements = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(20), default='Not')  # pending, submitted, approved
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

class Readiness(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    deliverable_id = db.Column(db.Integer, db.ForeignKey('deliverable.id'), nullable=False)
    readiness_name = db.Column(db.String(200), nullable=False)
    readiness_level = db.Column(db.String(50), nullable=True)  # e.g., 'Not Started', 'In Progress', 'Completed'

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    deliverable_id = db.Column(db.Integer, db.ForeignKey('deliverable.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ProgressReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    startup_id = db.Column(db.Integer, db.ForeignKey('startup.id'), nullable=False)
    submitted_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    achievements = db.Column(db.Text, nullable=True)
    challenges = db.Column(db.Text, nullable=True)
    next_steps = db.Column(db.Text, nullable=True)
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)

# ==================== DECORATORS ====================

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def super_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if not user or user.role != 'super_admin':
            flash('Access denied. Super admin privileges required.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if not user or user.role not in ['super_admin', 'admin']:
            flash('Access denied. Admin privileges required.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# ==================== ROUTES ====================
x = 0
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            flash(f'Welcome back, {user.username}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/settings')
def settings():
    return render_template('settings.html')

@app.route('/view_milestone', methods=['GET', 'POST'])
def view_milestone():
    
    startup_id = request.form.get('startup_id', type=int) or request.args.get('startup_id', type=int)
    index = request.form.get('index', type=int) or request.args.get('index', type=int)

    if startup_id and index:
        # 1. Query muna
        exists = Milestone.query.filter_by(
            startup_id=startup_id,
            milestone_progress=index
        ).first()

        # 2. Insert only if not exists
        if not exists:
            milestone = Milestone(startup_id=startup_id, milestone_progress=index)
            db.session.add(milestone)
            db.session.commit()
        else:
            milestone = exists

    # fetch milestone group id
    milestonegroup_id = Milestone.query.filter_by(
        startup_id=startup_id,
        milestone_progress=index
    ).first()

    # fetch existing readiness options
    existing_readiness = Readiness.query.join(Deliverable).filter(
        Deliverable.milestonegroup_id == milestonegroup_id.id
    ).all()

    existing_comments = Comment.query.join(Deliverable).filter(
        Deliverable.milestonegroup_id == milestonegroup_id.id
    ).all()

    exiting_requirements = Deliverable.query.filter_by(
        milestonegroup_id=milestonegroup_id.id
    ).all()

    if request.method == 'POST':
        due_date = request.form.get('due_date')
        comments = request.form.get('comments')
        requirements = request.form.get('requirements') 
        deliverable_name = request.form.get('deliverable_name')

        existing_deliverable = Deliverable.query.filter_by( 
            milestonegroup_id=milestonegroup_id.id, 
            deliverable_name=deliverable_name 
        ).first()

        if not existing_deliverable:

            if milestonegroup_id.status == 'not':
                milestonegroup_id.status = 'pending'
                db.session.commit()
            
            # file upload handling
            filename_final = f'final_{deliverable_name}_{datetime.utcnow().strftime("%Y%m%d%H%M%S")}.txt'

            new_deliverable = Deliverable(
                milestonegroup_id=milestonegroup_id.id,
                deliverable_name=deliverable_name,
                upload_file=filename_final,
                due_date=datetime.strptime(due_date, '%Y-%m-%d').date() if due_date else None,
                requirements=requirements,
                status='Pending'
            )
            db.session.add(new_deliverable)
            db.session.commit()

            session['current_deliverable_id'] = new_deliverable.id
            deliverable_id = session.get('current_deliverable_id')

            # Readiness options handling
            checked_options = request.form.getlist('options')
            for option in checked_options:
                existing_readiness = Readiness.query.filter_by(
                    deliverable_id=deliverable_id,
                    readiness_name=option
                ).first()
                if not existing_readiness:
                    readiness = Readiness(
                        deliverable_id=deliverable_id,
                        readiness_name=option,
                    )
                    db.session.add(readiness)

            # comments handling
            existing_comment = Comment.query.filter_by(
                deliverable_id=deliverable_id,
                user_id=session['user_id'],
                content=comments
            ).first()
            if not existing_comment:
                comment = Comment(
                    deliverable_id=deliverable_id,
                    user_id=session['user_id'],
                    content=comments
                )
                db.session.add(comment)
            db.session.commit()
        else:
            print(milestonegroup_id.id, deliverable_name)
            flash('Deliverable already exists. Please try again.', 'danger')
            return redirect(url_for('view_milestone', startup_id=startup_id, index=index))
    

    deliverableStatus = {int(d.deliverable_name): d.status for d in Deliverable.query.filter_by(milestonegroup_id=milestonegroup_id.id).all()}
    
    readiness_options = [r.readiness_name for r in existing_readiness]

    comment_context = [c.content for c in existing_comments]

    comment_user_ids = [c.user_id for c in existing_comments]
    user_names = [User.query.get(user_id).username for user_id in comment_user_ids]

    requirements_list = [r.requirements for r in exiting_requirements]


    return render_template('view_milestone.html', 
                           deliverableStatus=deliverableStatus, 
                           readiness_name=readiness_options, 
                           comment_context=comment_context, 
                           user_name=user_names,
                           requirements_list=requirements_list)


@app.route('/download_attachfile')
def download_attachfile():
    tempfile = Temporaryfile.query.get(1)
    if tempfile:
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], tempfile.filename)
        if os.path.exists(filepath):
            return redirect(url_for('static', filename=f'uploads/{tempfile.filename}'))
    flash('File not found.', 'danger')
    return redirect(url_for('view_milestone.html'))

@app.route('/dashboard')
@login_required
def dashboard():
    user = User.query.get(session['user_id'])
    
    if user.role == 'super_admin':
        admins = User.query.filter_by(role='admin').all()
        incubatees = User.query.filter_by(role='incubatee').all()
        startups = Startup.query.all()
        return render_template('super_admin_dashboard.html', 
                             user=user, admins=admins, 
                             incubatees=incubatees, startups=startups)
    
    elif user.role == 'admin':
        startups = Startup.query.all()
        recent_reports = ProgressReport.query.order_by(ProgressReport.submitted_at.desc()).limit(10).all()
        return render_template('admin_dashboard.html', 
                             user=user, startups=startups, 
                             recent_reports=recent_reports)
    
    else:  # incubatee
        memberships = StartupMember.query.filter_by(user_id=user.id).all()
        my_startups = [m.startup for m in memberships]
        return render_template('incubatee_dashboard.html', 
                             user=user, startups=my_startups)

@app.route("/")
def ms():
    return render_template('edit_startup.html', x=x)

# addmilestone
@app.route("/add")
def add_ms():
    global x
    x += 1
    return redirect(url_for("ms"))


# ==================== SUPER ADMIN ROUTES ====================

@app.route('/super_admin/add_admin', methods=['GET', 'POST'])
@super_admin_required
def add_admin():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('add_admin'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already exists', 'danger')
            return redirect(url_for('add_admin'))
        
        new_admin = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            role='admin',
            created_by=session['user_id']
        )
        
        db.session.add(new_admin)
        db.session.commit()
        
        flash(f'Admin {username} created successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('add_admin.html')

@app.route('/super_admin/delete_user/<int:user_id>')
@super_admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    
    if user.role == 'super_admin':
        flash('Cannot delete super admin users', 'danger')
        return redirect(url_for('dashboard'))
    
    db.session.delete(user)
    db.session.commit()
    flash(f'User {user.username} deleted successfully', 'success')
    return redirect(url_for('dashboard'))


@app.route('/super_admin/temp_file/', methods=['GET', 'POST'])
@super_admin_required
def add_tempfile():
    user = User.query.get(session['user_id'])
    file = request.files.get('temp_file')

    if file:
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        tempfile = Temporaryfile.query.get(1)
        if not tempfile:
            tempfile = Temporaryfile(filename=filename)
            db.session.add(tempfile)
        else:
            tempfile.filename = filename
            tempfile.uploaded_at = datetime.utcnow()
        db.session.commit()

        flash('Temporary file uploaded successfully!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('temp_file.html', user=user)

# ==================== ADMIN ROUTES ====================

# Add Startup
@app.route('/admin/add_startup', methods=['GET', 'POST'])
@admin_required
def add_startup():
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        industry = request.form.get('industry')
        stage = request.form.get('stage')
        email = request.form.get('email')
        contact_number = request.form.get('contactnumber')
        
        # Handle logo upload
        logo_path = None
        if 'logo' in request.files:
            file = request.files['logo']
            if file and file.filename:
                filename = secure_filename(file.filename)
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_')
                filename = timestamp + filename
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                logo_path = filename
        
        new_startup = Startup(
            name=name,
            description=description,
            logo=logo_path,
            industry=industry,
            stage=stage,
            owner_id=session['user_id'],
            email=email,
            contact_number=contact_number
        )
        
        db.session.add(new_startup)
        db.session.commit()
        
        flash(f'Startup {name} created successfully!', 'success')

        session['current_startup_id'] = new_startup.id
        return redirect(url_for('register_incubatee'))


    return render_template('add_startup.html')

# Register Incubatee and assign to Startup
@app.route('/admin/register_incubatee', methods=['GET', 'POST'])
@admin_required 
def register_incubatee():
    startup_id = session.get('current_startup_id')
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        first_name = request.form.get('firstname')
        contact_number = request.form.get('contactnumber')
        role = request.form.get('role') or "Incubatee"

        # Check duplicates
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('register_incubatee'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already exists', 'danger')
            return redirect(url_for('register_incubatee'))
            
        # Create new incubatee user
        new_user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            role='incubatee',
            created_by=session['user_id'],
            first_name=first_name,
            contact_number=contact_number
        )
        db.session.add(new_user)
        db.session.commit()

        # Check if already a member
        existing = StartupMember.query.filter_by(
            startup_id=startup_id, 
            user_id=new_user.id
        ).first()
    
        if existing:
            flash('User is already a member of this startup', 'warning')
        else:
            new_member = StartupMember(
                startup_id=startup_id,
                user_id=new_user.id,
                role=role
            )
            db.session.add(new_member)
            db.session.commit()

            flash(f'Incubatee {username} registered successfully!', 'success')
            return redirect(url_for('register_incubatee', startup_id=startup_id))  # or back to incubatee form if you prefer

    return render_template('register_incubatee.html', startup_id=startup_id)

@app.route('/admin/edit_startup/<int:startup_id>', methods=['GET', 'POST'])
@admin_required
def edit_startup(startup_id):
    startup = Startup.query.get_or_404(startup_id)
    
    if request.method == 'POST':
        startup.name = request.form.get('name')
        startup.description = request.form.get('description')
        startup.industry = request.form.get('industry')
        startup.stage = request.form.get('stage')
        
        # Handle logo upload
        if 'logo' in request.files:
            file = request.files['logo']
            if file and file.filename:
                filename = secure_filename(file.filename)
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_')
                filename = timestamp + filename
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                startup.logo = filename
        
        db.session.commit()
        flash('Startup updated successfully!', 'success')
        return redirect(url_for('edit_startup', startup_id=startup_id))
    
    all_users = User.query.filter_by(role='incubatee').all()
    members = StartupMember.query.filter_by(startup_id=startup_id).all()
    milestones = Milestone.query.filter_by(startup_id=startup_id).all()

    # Query milestones for this startup
    milestonesGroup = {m.milestone_progress: m.status for m in Milestone.query.filter_by(startup_id=startup_id).all()}
    print(milestonesGroup)
    
    return render_template('edit_startup.html', 
                         startup=startup, 
                         all_users=all_users,
                         members=members,
                         milestones=milestones,
                         milestonesGroup=milestonesGroup)

@app.route('/admin/add_member/<int:startup_id>', methods=['POST'])
@admin_required
def add_member(startup_id):
    user_id = request.form.get('user_id')
    role = request.form.get('role')
    
    existing = StartupMember.query.filter_by(
        startup_id=startup_id, 
        user_id=user_id
    ).first()
    
    if existing:
        flash('User is already a member of this startup', 'warning')
    else:
        new_member = StartupMember(
            startup_id=startup_id,
            user_id=user_id,
            role=role
        )
        db.session.add(new_member)
        db.session.commit()
        flash('Member added successfully!', 'success')
    
    return redirect(url_for('edit_startup', startup_id=startup_id))

@app.route('/admin/remove_member/<int:member_id>')
@admin_required
def remove_member(member_id):
    member = StartupMember.query.get_or_404(member_id)
    startup_id = member.startup_id
    db.session.delete(member)
    db.session.commit()
    flash('Member removed successfully', 'success')
    return redirect(url_for('edit_startup', startup_id=startup_id))

@app.route('/admin/add_milestone/<int:startup_id>', methods=['POST'])
@admin_required
def add_milestone(startup_id):
    title = request.form.get('title')
    description = request.form.get('description')
    category = request.form.get('category')
    due_date_str = request.form.get('due_date')
    achieved_before = request.form.get('achieved_before') == 'on'
    
    due_date = None
    if due_date_str:
        due_date = datetime.strptime(due_date_str, '%Y-%m-%d').date()
    
    new_milestone = Milestone(
        startup_id=startup_id,
        title=title,
        description=description,
        category=category,
        due_date=due_date,
        achieved_before_incubation=achieved_before,
        status='completed' if achieved_before else 'pending',
        completed_at=datetime.utcnow() if achieved_before else None
    )
    
    db.session.add(new_milestone)
    db.session.commit()
    flash('Milestone added successfully!', 'success')
    return redirect(url_for('edit_startup', startup_id=startup_id))

@app.route('/admin/delete_milestone/<int:milestone_id>')
@admin_required
def delete_milestone(milestone_id):
    milestone = Milestone.query.get_or_404(milestone_id)
    startup_id = milestone.startup_id
    db.session.delete(milestone)
    db.session.commit()
    flash('Milestone deleted successfully', 'success')
    return redirect(url_for('edit_startup', startup_id=startup_id))





# ==================== INCUBATEE ROUTES ====================

@app.route('/incubatee/submit_progress/<int:startup_id>', methods=['GET', 'POST'])
@login_required
def submit_progress(startup_id):
    startup = Startup.query.get_or_404(startup_id)
    
    # Check if user is a member
    member = StartupMember.query.filter_by(
        startup_id=startup_id,
        user_id=session['user_id']
    ).first()
    
    if not member:
        flash('You are not a member of this startup', 'danger')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        achievements = request.form.get('achievements')
        challenges = request.form.get('challenges')
        next_steps = request.form.get('next_steps')
        
        report = ProgressReport(
            startup_id=startup_id,
            submitted_by=session['user_id'],
            title=title,
            description=description,
            achievements=achievements,
            challenges=challenges,
            next_steps=next_steps
        )
        
        db.session.add(report)
        db.session.commit()
        
        flash('Progress report submitted successfully!', 'success')
        return redirect(url_for('view_startup_progress', startup_id=startup_id))
    
    return render_template('submit_progress.html', startup=startup)

@app.route('/view_startup/<int:startup_id>')
@login_required
def view_startup_progress(startup_id):
    startup = Startup.query.get_or_404(startup_id)
    user = User.query.get(session['user_id'])
    
    # Check access
    if user.role not in ['super_admin', 'admin']:
        member = StartupMember.query.filter_by(
            startup_id=startup_id,
            user_id=user.id
        ).first()
        if not member:
            flash('Access denied', 'danger')
            return redirect(url_for('dashboard'))
    
    milestones = Milestone.query.filter_by(startup_id=startup_id).all()
    reports = ProgressReport.query.filter_by(startup_id=startup_id).order_by(
        ProgressReport.submitted_at.desc()
    ).all()
    milestonesGroup = {m.milestone_progress: m.status for m in Milestone.query.filter_by(startup_id=startup_id).all()}
    
    return render_template('view_startup.html', 
                         startup=startup, 
                         milestones=milestones,
                         reports=reports,
                         milestonesGroup=milestonesGroup)

# ==================== INITIALIZE DATABASE ====================

@app.route('/init_db')
def init_db():
    db.create_all()
    
    # Create super admin if doesn't exist
    if not User.query.filter_by(username='superadmin').first():
        super_admin = User(
            username='superadmin',
            email='superadmin@incubator.com',
            password_hash=generate_password_hash('admin123'),
            role='super_admin'
            
        )
        db.session.add(super_admin)
        db.session.commit()
        return 'Database initialized! Super Admin created (username: superadmin, password: admin123)'
    
    return 'Database already initialized'

# ==================== RUN APP ====================

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)