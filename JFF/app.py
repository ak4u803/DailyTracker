from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, abort, current_app
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime, timedelta
import os
import re
import secrets
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from email_validator import validate_email, EmailNotValidError
from dotenv import load_dotenv
import json
import pandas as pd
from datetime import datetime, timezone

# Load environment variables
load_dotenv()

# Configure security headers
csp = {
    'default-src': ["'self'"],
    'style-src': [
        "'self'",
        'https://cdn.jsdelivr.net',
        'https://fonts.googleapis.com',
        "'unsafe-inline'"  # Required for some Bootstrap features
    ],
    'script-src': [
        "'self'",
        'https://cdn.jsdelivr.net',
        'https://code.jquery.com',
        'https://cdnjs.cloudflare.com',
        "'unsafe-inline'"  # Required for some Bootstrap features
    ],
    'img-src': [
        "'self'",
        'data:',
        'https://images.unsplash.com',
        'https://*.unsplash.com'
    ],
    'font-src': [
        "'self'",
        'https://cdn.jsdelivr.net',
        'https://fonts.gstatic.com',
        'data:'
    ],
    'connect-src': ["'self'"],
    'frame-ancestors': ["'none'"],
    'form-action': ["'self'"],
    'object-src': ["'none'"],
    'base-uri': ["'self'"],
    'frame-src': ["'self'"],
    'worker-src': ["'self'"],
    'media-src': ["'self'"],
    'manifest-src': ["'self'"]
}

app = Flask(__name__)

# Add csp_nonce function to template context
@app.context_processor
def inject_csp_nonce():
    return {'csp_nonce': lambda: request.csp_nonce if hasattr(request, 'csp_nonce') else ''}

# Load configuration from environment variables
app.config.update(
    SECRET_KEY=os.getenv('SECRET_KEY', 'dev-key-change-in-production'),
    SQLALCHEMY_DATABASE_URI=os.getenv('DATABASE_URL', 'sqlite:///lifetracker.db'),
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SESSION_COOKIE_SECURE=os.getenv('SESSION_COOKIE_SECURE', 'True') == 'True',
    SESSION_COOKIE_HTTPONLY=os.getenv('SESSION_COOKIE_HTTPONLY', 'True') == 'True',
    SESSION_COOKIE_SAMESITE=os.getenv('SESSION_COOKIE_SAMESITE', 'Lax'),
    PERMANENT_SESSION_LIFETIME=int(os.getenv('PERMANENT_SESSION_LIFETIME', 3600)),
    RATELIMIT_DEFAULT=os.getenv('RATELIMIT_DEFAULT', '100/hour'),
    RATELIMIT_LOGIN=os.getenv('RATELIMIT_LOGIN', '5/5minute')
)

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.session_protection = 'strong'

# Initialize security headers
talisman = Talisman(
    app,
    force_https=app.config['SESSION_COOKIE_SECURE'],
    strict_transport_security=app.config['SESSION_COOKIE_SECURE'],
    session_cookie_secure=app.config['SESSION_COOKIE_SECURE'],
    content_security_policy=csp,
    content_security_policy_nonce_in=['script-src'],
    content_security_policy_report_uri=None,
    # Only enforce CSP in production
    content_security_policy_report_only=app.debug,
    force_https_permanent=False,
    force_file_save=False,
    frame_options='DENY',
    frame_options_allow_from=None,
    strict_transport_security_include_subdomains=True,
    strict_transport_security_max_age=31536000,  # 1 year
    strict_transport_security_preload=True,
    referrer_policy='strict-origin-when-cross-origin',
    session_cookie_http_only=app.config['SESSION_COOKIE_HTTPONLY'],
    session_cookie_samesite=app.config['SESSION_COOKIE_SAMESITE']
)

# Add CSP report only in debug mode
if app.debug:
    @app.after_request
    def per_request_callbacks(response):
        response.headers['Content-Security-Policy-Report-Only'] = response.headers.get('Content-Security-Policy')
        response.headers['Content-Security-Policy'] = ""
        return response

# Initialize rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[app.config['RATELIMIT_DEFAULT']],
    storage_uri='memory://'
)

# Account lockout tracking
failed_login_attempts = {}

# Password policy configuration
PASSWORD_POLICY = {
    'min_length': int(os.getenv('MIN_PASSWORD_LENGTH', 12)),
    'require_special': os.getenv('REQUIRE_SPECIAL_CHAR', 'True') == 'True',
    'require_number': os.getenv('REQUIRE_NUMBER', 'True') == 'True',
    'require_uppercase': os.getenv('REQUIRE_UPPERCASE', 'True') == 'True',
    'require_lowercase': os.getenv('REQUIRE_LOWERCASE', 'True') == 'True'
}

# Account lockout configuration
ACCOUNT_LOCKOUT = {
    'max_attempts': int(os.getenv('MAX_LOGIN_ATTEMPTS', 5)),
    'lockout_time': int(os.getenv('LOCKOUT_TIME', 900))  # 15 minutes
}

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    last_login_at = db.Column(db.DateTime, nullable=True)
    login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    activities = db.relationship('Activity', backref='user', lazy=True)
    
    def is_locked(self):
        if self.locked_until and datetime.utcnow() < self.locked_until:
            return True
        if self.locked_until and datetime.utcnow() >= self.locked_until:
            self.locked_until = None
            self.login_attempts = 0
            db.session.commit()
        return False
    
    def record_failed_attempt(self):
        self.login_attempts += 1
        if self.login_attempts >= ACCOUNT_LOCKOUT['max_attempts']:
            self.locked_until = datetime.utcnow() + timedelta(seconds=ACCOUNT_LOCKOUT['lockout_time'])
        db.session.commit()
    
    def record_successful_login(self):
        self.last_login_at = datetime.utcnow()
        self.login_attempts = 0
        self.locked_until = None
        db.session.commit()

class Activity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50))
    duration = db.Column(db.Float)  # in hours
    date = db.Column(db.Date, nullable=False, default=datetime.utcnow)
    mood = db.Column(db.Integer)  # 1-5 scale
    notes = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class BrowserHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    url = db.Column(db.Text, nullable=False)
    title = db.Column(db.Text)
    visit_count = db.Column(db.Integer, default=1)
    last_visit_time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    domain = db.Column(db.String(255))
    time_spent = db.Column(db.Float, default=0)  # in seconds
    date = db.Column(db.Date, nullable=False, default=datetime.utcnow)
    category = db.Column(db.String(100))
    
    @classmethod
    def process_history_file(cls, file, user_id):
        try:
            # Read and parse the JSON file
            history_data = json.load(file)
            
            # Process each history entry
            for entry in history_data:
                # Extract domain from URL
                domain = ''
                try:
                    domain = entry.get('url', '').split('//')[-1].split('/')[0]
                except:
                    domain = 'unknown'
                
                # Convert timestamp to datetime
                last_visit = datetime.fromtimestamp(entry.get('last_visit_time', 0) / 1000000, tz=timezone.utc)
                
                # Check if this URL already exists for the user
                history = cls.query.filter_by(user_id=user_id, url=entry.get('url')).first()
                
                if history:
                    # Update existing entry
                    history.visit_count += entry.get('visit_count', 1)
                    history.last_visit_time = last_visit
                    history.time_spent += entry.get('time_spent', 0)
                else:
                    # Create new entry
                    history = cls(
                        user_id=user_id,
                        url=entry.get('url'),
                        title=entry.get('title', 'No Title'),
                        visit_count=entry.get('visit_count', 1),
                        last_visit_time=last_visit,
                        domain=domain,
                        time_spent=entry.get('time_spent', 0),
                        date=last_visit.date()
                    )
                    db.session.add(history)
            
            db.session.commit()
            return True, "History processed successfully"
            
        except Exception as e:
            db.session.rollback()
            return False, f"Error processing history: {str(e)}"

def validate_password(password):
    """Validate password against security policy."""
    if len(password) < PASSWORD_POLICY['min_length']:
        return False, f"Password must be at least {PASSWORD_POLICY['min_length']} characters long"
    
    if PASSWORD_POLICY['require_uppercase'] and not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
        
    if PASSWORD_POLICY['require_lowercase'] and not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
        
    if PASSWORD_POLICY['require_number'] and not re.search(r'\d', password):
        return False, "Password must contain at least one number"
        
    if PASSWORD_POLICY['require_special'] and not re.search(r'[!@#$%^&*(),.?\":{}|<>]', password):
        return False, "Password must contain at least one special character"
        
    return True, ""

def check_account_lockout(user):
    """Check if account is locked and return remaining time if locked."""
    if user and user.is_locked():
        remaining = user.locked_until - datetime.utcnow()
        return True, remaining.seconds // 60  # Return minutes remaining
    return False, 0

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/dashboard')
@login_required
def dashboard():
    # Get activities for the last 7 days
    week_ago = datetime.utcnow() - timedelta(days=7)
    recent_activities = Activity.query.filter(
        Activity.user_id == current_user.id,
        Activity.date >= week_ago.date()
    ).order_by(Activity.date.desc()).all()
    
    return render_template('dashboard.html', activities=recent_activities)

@app.route('/add_activity', methods=['GET', 'POST'])
@login_required
def add_activity():
    if request.method == 'POST':
        name = request.form.get('name')
        category = request.form.get('category')
        duration = float(request.form.get('duration', 0))
        mood = int(request.form.get('mood', 3))
        notes = request.form.get('notes', '')
        
        activity = Activity(
            name=name,
            category=category,
            duration=duration,
            mood=mood,
            notes=notes,
            user_id=current_user.id
        )
        
        db.session.add(activity)
        db.session.commit()
        
        flash('Activity added successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('add_activity.html')

@app.route('/analytics')
@login_required
def analytics():
    return render_template('analytics.html')

@app.route('/browser-history', methods=['GET', 'POST'])
@login_required
def browser_history():
    if request.method == 'POST':
        if 'history_file' not in request.files:
            flash('No file selected', 'danger')
            return redirect(request.url)
            
        file = request.files['history_file']
        if file.filename == '':
            flash('No file selected', 'danger')
            return redirect(request.url)
            
        if file and file.filename.endswith('.json'):
            success, message = BrowserHistory.process_history_file(file, current_user.id)
            if success:
                flash('Browser history uploaded successfully!', 'success')
            else:
                flash(message, 'danger')
            return redirect(url_for('browser_history_insights'))
        else:
            flash('Please upload a valid JSON file', 'danger')
            
    return render_template('browser_history.html')

@app.route('/browser-history/insights')
@login_required
def browser_history_insights():
    # Get browsing data for the last 30 days
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    
    # Get top visited sites
    top_sites = db.session.query(
        BrowserHistory.domain,
        db.func.sum(BrowserHistory.visit_count).label('total_visits'),
        db.func.sum(BrowserHistory.time_spent).label('total_time_spent')
    ).filter(
        BrowserHistory.user_id == current_user.id,
        BrowserHistory.last_visit_time >= thirty_days_ago
    ).group_by(BrowserHistory.domain).order_by(db.desc('total_visits')).limit(10).all()
    
    # Get daily usage
    daily_usage = db.session.query(
        BrowserHistory.date,
        db.func.sum(BrowserHistory.time_spent).label('total_time')
    ).filter(
        BrowserHistory.user_id == current_user.id,
        BrowserHistory.last_visit_time >= thirty_days_ago
    ).group_by(BrowserHistory.date).order_by(BrowserHistory.date).all()
    
    # Get category distribution (you can implement category detection based on domains)
    category_data = db.session.query(
        db.func.count(BrowserHistory.id).label('count'),
        db.func.sum(BrowserHistory.time_spent).label('time_spent')
    ).filter(
        BrowserHistory.user_id == current_user.id,
        BrowserHistory.last_visit_time >= thirty_days_ago
    ).first()
    
    # Prepare data for charts
    chart_data = {
        'labels': [str(day[0]) for day in daily_usage],
        'time_spent': [round(day[1]/3600, 2) for day in daily_usage]  # Convert to hours
    }
    
    return render_template('browser_history_insights.html',
                         top_sites=top_sites,
                         chart_data=chart_data,
                         category_data=category_data)

# Authentication routes
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit(app.config['RATELIMIT_LOGIN'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember', 'off') == 'on'
        
        if not username or not password:
            flash('Username and password are required', 'error')
            return render_template('login.html')
        
        user = User.query.filter_by(username=username).first()
        
        # Check if account is locked
        if user and user.is_locked():
            remaining = (user.locked_until - datetime.utcnow()).seconds // 60
            flash(f'Account locked. Try again in {remaining} minutes.', 'error')
            return render_template('login.html')
        
        # Validate credentials
        if user and check_password_hash(user.password_hash, password):
            user.record_successful_login()
            
            # Clear the existing session and create a new one
            session.clear()
            
            # Log the user in with remember me option
            login_user(user, remember=remember)
            
            # Ensure we have a fresh session
            session.modified = True
            
            # Set session lifetime
            app.permanent_session_lifetime = timedelta(seconds=app.config['PERMANENT_SESSION_LIFETIME'])
            
            # Generate a new CSRF token if one doesn't exist
            if 'csrf_token' not in session:
                session['csrf_token'] = secrets.token_hex(16)
            
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        
        # Record failed login attempt
        if user:
            user.record_failed_attempt()
            attempts_left = ACCOUNT_LOCKOUT['max_attempts'] - user.login_attempts
            if attempts_left > 0:
                flash(f'Invalid username or password. {attempts_left} attempts remaining.', 'error')
            else:
                flash(f'Account locked for {ACCOUNT_LOCKOUT["lockout_time"] // 60} minutes due to too many failed attempts.', 'error')
        else:
            # Don't reveal if user exists or not
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit('5 per hour')
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Validate input
        if not all([username, email, password, confirm_password]):
            flash('All fields are required', 'error')
            return render_template('register.html')
            
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('register.html')
            
        # Validate password strength
        is_valid, message = validate_password(password)
        if not is_valid:
            flash(f'Password validation failed: {message}', 'error')
            return render_template('register.html')
            
        # Validate email
        try:
            # Validate and normalize the email address
            valid = validate_email(email)
            email = valid.email  # Normalized email
        except EmailNotValidError as e:
            flash('Invalid email address', 'error')
            return render_template('register.html')
        
        # Check if username or email already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return render_template('register.html')
            
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
            return render_template('register.html')
        
        # Create new user
        hashed_password = generate_password_hash(
            password,
            method='pbkdf2:sha256',
            salt_length=16
        )
        
        new_user = User(
            username=username,
            email=email,
            password_hash=hashed_password
        )
        
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Registration error: {str(e)}')
            flash('An error occurred during registration. Please try again.', 'error')
    
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# Admin required decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Admin routes
@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    from datetime import datetime, timedelta
    
    # Get user statistics
    user_count = User.query.count()
    activity_count = Activity.query.count()
    
    # Count active users today
    today = datetime.utcnow().date()
    active_today_count = db.session.query(Activity.user_id.distinct())\
        .filter(Activity.date >= today).count()
    
    # Count locked accounts
    locked_accounts_count = User.query.filter(
        User.locked_until.isnot(None),
        User.locked_until > datetime.utcnow()
    ).count()
    
    # Get recent users
    recent_users = User.query.order_by(User.created_at.desc()).limit(10).all()
    
    return render_template('admin/dashboard.html',
                         user_count=user_count,
                         activity_count=activity_count,
                         active_today_count=active_today_count,
                         locked_accounts_count=locked_accounts_count,
                         recent_users=recent_users)

@app.route('/admin/user/<int:user_id>/toggle_admin', methods=['POST'])
@login_required
@admin_required
def toggle_admin(user_id):
    if current_user.id == user_id:
        flash('You cannot modify your own admin status.', 'danger')
        return redirect(url_for('admin_dashboard'))
        
    user = User.query.get_or_404(user_id)
    user.is_admin = not user.is_admin
    db.session.commit()
    
    action = 'granted admin privileges to' if user.is_admin else 'revoked admin privileges from'
    flash(f'Successfully {action} {user.username}.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/user/<int:user_id>/toggle_lock', methods=['POST'])
@login_required
@admin_required
def toggle_user_lock(user_id):
    if current_user.id == user_id:
        flash('You cannot lock your own account.', 'danger')
        return redirect(url_for('admin_dashboard'))
        
    user = User.query.get_or_404(user_id)
    
    if user.is_locked():
        user.locked_until = None
        user.login_attempts = 0
        action = 'unlocked'
    else:
        user.locked_until = datetime.utcnow() + timedelta(days=365)  # Lock for a year
        action = 'locked'
    
    db.session.commit()
    flash(f'Successfully {action} user {user.username}.', 'success')
    return redirect(url_for('admin_dashboard'))

# API endpoints for analytics
@app.route('/api/activities')
@login_required
def get_activities():
    # Get activities for the last 30 days
    month_ago = datetime.utcnow() - timedelta(days=30)
    activities = Activity.query.filter(
        Activity.user_id == current_user.id,
        Activity.date >= month_ago.date()
    ).all()
    
    # Convert activities to a list of dictionaries
    activities_data = [{
        'id': a.id,
        'name': a.name,
        'category': a.category,
        'duration': a.duration,
        'date': a.date.isoformat(),
        'mood': a.mood,
        'notes': a.notes
    } for a in activities]
    
    return jsonify(activities_data)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
