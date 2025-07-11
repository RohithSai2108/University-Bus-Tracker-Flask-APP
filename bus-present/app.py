from datetime import datetime, timedelta, UTC
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import requests
import os
from flask_socketio import SocketIO, emit
from models import db, User, Bus, Route, Stop, Schedule, Issue, ActivityLog, RouteRequest, Notification, RouteStop
from flask_wtf.csrf import CSRFProtect
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField
from wtforms.validators import DataRequired
from functools import wraps
import mysql.connector
from mysql.connector import Error
from flask_migrate import Migrate  # Add this import
import math
from apis.location_api import location_api

# Remove DANGER_ZONE_CENTER, DANGER_ZONE_RADIUS_METERS, is_within_zone, and any geofence logic

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            abort(403)  # Forbidden access
        return f(*args, **kwargs)
    return decorated_function

try:
    from config import MAPPLS_API_KEY, SECRET_KEY, SQLALCHEMY_DATABASE_URI
except ImportError:
    MAPPLS_API_KEY = os.getenv('MAPPLS_API_KEY', 'your_mappls_api_key_here')
    SECRET_KEY = os.getenv('SECRET_KEY', 'your-secret-key_here')
    SQLALCHEMY_DATABASE_URI = os.getenv('SQLALCHEMY_DATABASE_URI', 'sqlite:///bus_tracker.db')

# Initialize Flask app
app = Flask(__name__)
app.config.from_object('config')  # Load all config variables from config.py
app.config['WTF_CSRF_ENABLED'] = True  # Enable CSRF protection

# Initialize extensions
csrf = CSRFProtect()
csrf.init_app(app)
db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
socketio = SocketIO(app)
migrate = Migrate(app, db)  # Add this line
app.register_blueprint(location_api)

# Define BASE_URL for network and localhost
BASE_URL = os.getenv('BASE_URL', 'http://localhost:5000')

@app.context_processor
def inject_now():
    return {'now': datetime.utcnow()}

@app.context_processor
def inject_config():
    return {'config': {'MAPPLS_API_KEY': MAPPLS_API_KEY}}

@app.context_processor
def inject_base_url():
    return {'BASE_URL': BASE_URL}

# Routes and API endpoints
@app.route('/api/update_user_location', methods=['POST'])
@login_required
def update_user_location():
    data = request.json
    lat = data.get('lat')
    lng = data.get('lng')
    print(f"[USER LOCATION UPDATE] Received: lat={lat}, lng={lng}, data={data}")
    try:
        lat = float(lat)
        lng = float(lng)
    except (TypeError, ValueError):
        print(f"[ERROR] Invalid lat/lng received: lat={lat}, lng={lng}")
        return jsonify({"error": "Invalid coordinates"}), 400
    session['user_location'] = {'lat': lat, 'lng': lng}
    return jsonify({"status": "success", "message": "Location updated", "base_url": BASE_URL})

@app.route('/api/bus_location/<int:bus_id>', methods=['POST'])
@login_required
def update_bus_location(bus_id):
    if current_user.role != 'driver':
        return jsonify({"error": "Unauthorized"}), 403
    data = request.json
    lat = data.get('lat')
    lng = data.get('lng')
    print(f"[DRIVER LOCATION UPDATE] Received for bus_id={bus_id}: lat={lat}, lng={lng}, data={data}")
    try:
        lat = float(lat)
        lng = float(lng)
    except (TypeError, ValueError):
        print(f"[ERROR] Invalid lat/lng received: lat={lat}, lng={lng}")
        return jsonify({"error": "Invalid coordinates"}), 400
    bus = Bus.query.get(bus_id)
    if bus:
        bus.current_lat = lat
        bus.current_lng = lng
        bus.last_updated = datetime.utcnow()
        db.session.commit()
        print(f"[DRIVER LOCATION UPDATE] Saved to DB: bus_id={bus_id}, lat={bus.current_lat}, lng={bus.current_lng}")
        # Get current route information
        current_schedule = Schedule.query.filter_by(
            bus_id=bus.id, 
            status='in-progress'
        ).first()
        route_name = current_schedule.route.name if current_schedule else 'No active route'
        # Emit location update to all clients
        socketio.emit('driver_location_update', {
            'driver_id': current_user.id,
            'driver_name': current_user.username,
            'bus_id': bus_id,
            'bus_name': bus.name,
            'route_name': route_name,
            'lat': lat,
            'lng': lng,
            'timestamp': datetime.utcnow().isoformat()
        }, broadcast=True)
        print(f"[DRIVER LOCATION UPDATE] Emitted: bus_id={bus_id}, lat={lat}, lng={lng}")
        return jsonify({
            "status": "success",
            "message": f"Bus #{bus_id} location updated",
            "base_url": BASE_URL
        })
    return jsonify({"status": "error", "message": "Bus not found"}), 404

@app.route('/api/submit_route_request', methods=['POST'])
@login_required
def submit_route_request():
    if current_user.role != 'student':
        return jsonify({"status": "error", "message": "Unauthorized"}), 403
    if not csrf.exempt:
        token = request.headers.get('X-CSRFToken')
        if not token or token != session.get('csrf_token'):
            return jsonify({"status": "error", "message": "Invalid CSRF token"}), 403
    data = request.get_json()
    if not data:
        return jsonify({"status": "error", "message": "No data provided"}), 400
    request_type = data.get('request_type')
    route_number = data.get('route_number')
    request_details = data.get('request_details')
    reason = data.get('reason')
    if not request_details or not reason:
        return jsonify({"status": "error", "message": "Missing required fields"}), 400
    try:
        new_request = RouteRequest(
            student_id=current_user.id,
            request_type=request_type,
            route_number=route_number,
            details=request_details,
            reason=reason,
            status='Pending'
        )
        db.session.add(new_request)
        db.session.commit()
        return jsonify({"status": "success", "message": "Request submitted successfully"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"status": "error", "message": f"Failed to submit request: {str(e)}"}), 500

@app.route('/api/submit_vehicle_status', methods=['POST'])
@login_required
def submit_vehicle_status():
    if current_user.role != 'driver':
        return jsonify({"error": "Unauthorized"}), 403
    data = request.json
    condition = data.get('condition')
    notes = data.get('notes')
    new_issue = Issue(description=f"Vehicle Status: {condition}, Notes: {notes}", reported_by=current_user.id, type='vehicle_report')
    db.session.add(new_issue)
    db.session.commit()
    return jsonify({"status": "success", "message": "Vehicle status submitted"})

@app.route('/api/start_route', methods=['POST'])
@login_required
def start_route():
    if current_user.role != 'driver':
        return jsonify({"error": "Unauthorized"}), 403
    data = request.json
    bus_id = data.get('bus_id')
    bus = Bus.query.get(bus_id)
    if bus:
        schedule = Schedule.query.filter_by(bus_id=bus.id, status='scheduled').first()
        if schedule:
            schedule.status = 'in-progress'
            db.session.commit()
            return jsonify({"status": "success", "message": "Route started"})
    return jsonify({"status": "error", "message": "No scheduled route to start"})

@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except (ValueError, TypeError):
        return None

@socketio.on('connect')
def handle_connect():
    if not current_user.is_authenticated:
        return False

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

@socketio.on('resolve_issue')
def handle_resolve_issue(data):
    issue = Issue.query.get(data['issue_id'])
    if issue:
        issue.status = 'Resolved'
        db.session.commit()
        emit('issue_resolved', {'issue_id': issue.id}, broadcast=True)

@app.route('/')
def index():
    return render_template('index.html')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    role = StringField('Role', validators=[DataRequired()])

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired()])
    role = StringField('Role', validators=[DataRequired()])

class ReportIssueForm(FlaskForm):
    issue = TextAreaField('Issue', validators=[DataRequired()])

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired()])

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    error_message = None  # Initialize error_message
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role')
        if not role:
            error_message = 'Please select a user type'
        else:
            user = User.query.filter_by(username=username, role=role).first()
            if user and user.check_password(password):
                login_user(user)
                if role == 'admin':
                    return redirect(url_for('admin_dashboard'))
                elif role == 'driver':
                    return redirect(url_for('driver_dashboard'))
                else:
                    return redirect(url_for('student_dashboard'))
            error_message = 'Invalid username/password combination or incorrect role'
    user = session.get('user')  # Example: Retrieve user from session
    return render_template('login.html', form=form, User=user, error_message=error_message)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        user_exists = User.query.filter_by(username=form.username.data).first()
        email_exists = User.query.filter_by(email=form.email.data).first()
        if user_exists:
            flash('Username already exists', 'danger')
        elif email_exists:
            flash('Email already exists', 'danger')
        elif form.password.data != form.confirm_password.data:
            flash('Passwords do not match', 'danger')
        else:
            new_user = User(username=form.username.data, email=form.email.data, role=form.role.data)
            new_user.set_password(form.password.data)
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    session.clear()
    flash('You have been logged out', 'info')  # Flash message for logout
    return redirect(url_for('login'))  # Redirect to login page

@app.route('/student/dashboard')
@login_required
def student_dashboard():
    if current_user.role != 'student':
        flash('Access denied', 'danger')
        return redirect(url_for('login'))
    # Ensure flash messages are not redundantly rendered
    active_buses = Bus.query.filter_by(status='active').all()
    all_routes = Route.query.all()
    active_schedules = Schedule.query.filter_by(status='in-progress').all()
    recent_issues = Issue.query.filter_by(type='driver_report', status='Pending').order_by(Issue.reported_at.desc()).limit(5).all()
    return render_template('student_dashboard.html',
        buses=active_buses,
        routes=all_routes,
        schedules=active_schedules,
        recent_issues=recent_issues
    )

@app.route('/driver/dashboard')
@app.route('/driver/dashboard/<string:section>')
@login_required
def driver_dashboard(section='current-route'):
    if current_user.role != 'driver':
        flash('Access denied', 'danger')
        return redirect(url_for('login'))
    
    current_route = None
    schedules = []
    route_history = []
    issues_reported = []
    bus = None
    
    # Get driver's current bus
    bus = Bus.query.filter_by(driver_id=current_user.id).first()
    # Initialize current_route_data with a default value
    current_route_data = {
        'route_number': 'N/A',
        'route_name': 'No Active Route',
        'status': 'Not Started',
        'bus': 'N/A',
        'departure': 'N/A'
    }
    
    if bus:
        # Get current schedule (in-progress)
        current_schedule = Schedule.query.filter_by(bus_id=bus.id, status='in-progress').first()
        if current_schedule:
            current_route = Route.query.get(current_schedule.route_id)
            if current_route:
                current_route_data = {
                    'route_number': current_route.id,
                    'route_name': current_route.name,
                    'status': current_schedule.status,
                    'bus': bus.name,
                    'departure': current_schedule.departure_time.strftime('%I:%M %p') if current_schedule.departure_time else 'N/A'
                }
        
        # Get all schedules for today
        today = datetime.utcnow().date()
        schedules = Schedule.query.filter(
            Schedule.bus_id == bus.id,
            Schedule.departure_time >= datetime.combine(today, datetime.min.time()),
            Schedule.departure_time < datetime.combine(today + timedelta(days=1), datetime.min.time())
        ).all()
        
        # Get route history
        route_history = Schedule.query.filter_by(bus_id=bus.id).order_by(Schedule.departure_time.desc()).limit(10).all()
    
    # Get reported issues
    issues_reported = Issue.query.filter_by(reported_by=current_user.id).order_by(Issue.reported_at.desc()).all()
    
    return render_template('driver_dashboard.html',
        current_user=current_user,
        current_route_data=current_route_data,
        route_history=route_history,
        schedule=schedules,
        issues_reported=issues_reported,
        bus=bus,
        active_section=section,
        form=ReportIssueForm(),
        password_form=ChangePasswordForm()
    )

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('index'))
    
    # Get all necessary data
    buses = db.session.query(Bus).all()
    users = db.session.query(User).all()
    routes = db.session.query(Route).all()
    schedules = db.session.query(Schedule).all()
    issues = db.session.query(Issue).all()
    logs = db.session.query(ActivityLog).order_by(ActivityLog.timestamp.desc()).limit(10).all()
    route_requests = db.session.query(RouteRequest).order_by(RouteRequest.created_at.desc()).all()
    
    # Get active buses and their current status
    active_buses = [bus for bus in buses if bus.status == 'active']
    inactive_buses = [bus for bus in buses if bus.status == 'inactive']
    
    # Get active routes
    active_routes = [schedule for schedule in schedules if schedule.status == 'in-progress']
    
    # Get pending issues
    pending_issues = [issue for issue in issues if issue.status == 'Pending']
    urgent_issues = [issue for issue in issues if issue.urgency == 'urgent']
    
    # Get recent activity
    recent_activity = db.session.query(ActivityLog).order_by(ActivityLog.timestamp.desc()).limit(5).all()
    
    # Prepare data for the template
    template_data = {
        'current_user': current_user,
        'buses': buses,
        'users': users,
        'routes': routes,
        'schedules': schedules,
        'issues': issues,
        'logs': logs,
        'route_requests': route_requests,
        'active_buses': active_buses,
        'inactive_buses': inactive_buses,
        'active_routes': active_routes,
        'pending_issues': pending_issues,
        'urgent_issues': urgent_issues,
        'recent_activity': recent_activity,
        'User': User,
        'Schedule': Schedule,
        'Bus': Bus,
        'Route': Route,
        'Issue': Issue,
        'ActivityLog': ActivityLog,
        'RouteRequest': RouteRequest
    }
    
    return render_template('admin_dashboard.html', **template_data)

@app.route('/api/admin/update_bus_status', methods=['POST'])
@login_required
def update_bus_status():
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.json
    bus_id = data.get('bus_id')
    status = data.get('status')
    
    bus = Bus.query.get(bus_id)
    if bus:
        bus.status = status
        db.session.commit()
        
        # Log the activity
        log = ActivityLog(action=f'Bus {bus.name} status updated to {status}')
        db.session.add(log)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Bus status updated'})
    return jsonify({'error': 'Bus not found'}), 404

@app.route('/api/admin/assign_driver', methods=['POST'])
@login_required
def assign_driver():
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.json
    bus_id = data.get('bus_id')
    driver_id = data.get('driver_id')
    
    bus = Bus.query.get(bus_id)
    driver = User.query.get(driver_id)
    
    if bus and driver and driver.role == 'driver':
        bus.driver_id = driver_id
        db.session.commit()
        
        # Log the activity
        log = ActivityLog(action=f'Driver {driver.username} assigned to bus {bus.name}')
        db.session.add(log)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Driver assigned successfully'})
    return jsonify({'error': 'Invalid bus or driver'}), 400

@app.route('/api/admin/resolve_issue', methods=['POST'])
@login_required
def resolve_issue():
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.json
    issue_id = data.get('issue_id')
    resolution = data.get('resolution')
    
    issue = Issue.query.get(issue_id)
    if issue:
        issue.status = 'Resolved'
        issue.resolution = resolution
        db.session.commit()
        
        # Log the activity
        log = ActivityLog(action=f'Issue #{issue_id} resolved')
        db.session.add(log)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Issue resolved'})
    return jsonify({'error': 'Issue not found'}), 404

@app.route('/api/admin/process_route_request', methods=['POST'])
@login_required
def process_route_request():
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.json
    request_id = data.get('request_id')
    action = data.get('action')  # 'approve' or 'reject'
    comment = data.get('comment', '')
    
    route_request = RouteRequest.query.get(request_id)
    if route_request:
        if action == 'approve':
            route_request.status = 'Approved'
            # Implement route changes here if needed
        else:
            route_request.status = 'Rejected'
        
        route_request.admin_comment = comment
        db.session.commit()
        
        # Log the activity
        log = ActivityLog(action=f'Route request #{request_id} {action}ed')
        db.session.add(log)
        db.session.commit()
        
        return jsonify({'success': True, 'message': f'Request {action}ed'})
    return jsonify({'error': 'Request not found'}), 404

# API routes
@app.route('/api/bus_locations')
@login_required
def bus_locations():
    buses = Bus.query.all()
    return jsonify({
        'status': 'success',
        'buses': [
            {
                'id': bus.id,
                'name': bus.name,
                'status': bus.status,
                'current_lat': bus.current_lat,
                'current_lng': bus.current_lng,
                'last_updated': bus.last_updated.isoformat() if bus.last_updated else None,
                'driver': {
                    'id': bus.driver.id,
                    'username': bus.driver.username
                } if bus.driver else None
            } for bus in buses
        ]
    })

@app.route('/api/student/route')
@login_required
def student_route():
    if current_user.role != 'student':
        return jsonify({'error': 'Unauthorized'}), 403
    
    # Get the student's assigned bus and route
    bus = Bus.query.filter_by(driver_id=current_user.id).first()
    if not bus:
        return jsonify({'error': 'No bus assigned'}), 404
    
    route = Route.query.join(Schedule).filter(
        Schedule.bus_id == bus.id,
        Schedule.status == 'in-progress'
    ).first()
    
    if not route:
        return jsonify({'error': 'No active route'}), 404
    
    # Get route stops
    stops = Stop.query.filter_by(route_id=route.id).order_by(Stop.id).all()
    
    # Calculate next stop and ETA
    next_stop = None
    eta = None
    if bus.current_lat and bus.current_lng:
        # Find the closest upcoming stop
        for stop in stops:
            if not next_stop:
                next_stop = stop
                # Simple ETA calculation (can be improved with actual route distance and speed)
                eta = '5-10 minutes'
    
    return jsonify({
        'bus': {
            'id': bus.id,
            'name': bus.name,
            'status': bus.status,
            'current_lat': bus.current_lat,
            'current_lng': bus.current_lng,
            'last_updated': bus.last_updated.isoformat() if bus.last_updated else None
        },
        'route': {
            'id': route.id,
            'name': route.name,
            'stops': [{
                'id': stop.id,
                'name': stop.name,
                'lat': stop.lat,
                'lng': stop.lng
            } for stop in stops]
        },
        'nextStop': next_stop.name if next_stop else None,
        'eta': eta
    })

@socketio.on('connect')
def handle_connect():
    if not current_user.is_authenticated:
        return False

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

@socketio.on('bus_location_update')
def handle_bus_location_update(data):
    if not current_user.is_authenticated or current_user.role != 'driver':
        return
    
    bus = Bus.query.filter_by(driver_id=current_user.id).first()
    if not bus:
        return
    
    bus.current_lat = data['lat']
    bus.current_lng = data['lng']
    bus.last_updated = datetime.utcnow()
    db.session.commit()
    
    # Broadcast the update to all connected clients
    emit('bus_location_update', {
        'bus_id': bus.id,
        'lat': data['lat'],
        'lng': data['lng'],
        'status': bus.status,
        'last_updated': bus.last_updated.isoformat()
    }, broadcast=True)

@app.route('/api/bus_location/<int:bus_id>', methods=['POST'])
@login_required
def api_update_bus_location(bus_id):
    if current_user.role != 'driver':
        return jsonify({"error": "Unauthorized"}), 403
    data = request.json
    lat = data.get('lat')
    lng = data.get('lng')
    bus = Bus.query.get(bus_id)
    if bus:
        bus.current_lat = lat
        bus.current_lng = lng
        bus.last_updated = datetime.utcnow()
        db.session.commit()
    return jsonify({"status": "success"})

@app.route('/api/routes')
def api_routes():
    routes = [
        {"id": 1, "name": "Campus Loop", "stops": [{"id": 1, "name": "Main Gate", "lat": 40.7128, "lng": -74.0060}]},
        {"id": 2, "name": "Downtown Express", "stops": [{"id": 4, "name": "City Center", "lat": 40.7228, "lng": -74.0160}]}
    ]
    return jsonify(routes)

@app.route('/api/routes/<int:route_id>')
def api_route(route_id):
    route = None
    return jsonify(route if route else {"error": "Route not found"})

@app.route('/api/plan_route', methods=['POST'])
def plan_route():
    data = request.json
    origin = data['origin']
    destination = data['destination']
    url = "https://routes.googleapis.com/directions/v2:computeRoutes"
    headers = {"Content-Type": "application/json", "X-Goog-Api-Key": "YOUR_API_KEY"}
    body = {"origin": {"address": origin}, "destination": {"address": destination}, "travelMode": "DRIVE"}
    response = requests.post(url, json=body, headers=headers)
    return jsonify(response.json())

@app.route('/api/notifications/send', methods=['POST'])
@login_required
@admin_required
def send_notification():
    data = request.get_json()
    
    try:
        notification_type = data.get('type')
        message = data.get('message')
        priority = data.get('priority', 'normal')
        
        if not message:
            return jsonify({'success': False, 'message': 'Message is required'})

        # Get recipients based on notification type
        if notification_type == 'all':
            recipients = User.query.filter(User.role != 'admin').all()
        elif notification_type == 'drivers':
            recipients = User.query.filter_by(role='driver').all()
        elif notification_type == 'students':
            recipients = User.query.filter_by(role='student').all()
        elif notification_type == 'specific':
            recipient_ids = data.get('recipients', [])
            recipients = User.query.filter(User.id.in_(recipient_ids)).all()
        else:
            return jsonify({'success': False, 'message': 'Invalid notification type'})

        # Create notifications for each recipient
        for recipient in recipients:
            notification = Notification(
                message=message,
                user_id=recipient.id,
                type=priority
            )
            db.session.add(notification)

        db.session.commit()
        
        # Emit socket event for real-time updates
        socketio.emit('new_notification', {
            'message': message,
            'priority': priority,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }, room='notifications')

        return jsonify({
            'success': True,
            'message': f'Notification sent to {len(recipients)} recipients'
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

@app.route('/admin/schedules', methods=['GET', 'POST'])
@login_required
def manage_schedules():
    if current_user.role != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('login'))
    if request.method == 'POST':
        pass
    schedules = Schedule.query.all()
    return render_template('admin_schedules.html', schedules=schedules)

@app.route('/report_issue', methods=['POST'])
@login_required
def report_issue():
    form = ReportIssueForm()
    if form.validate_on_submit():
        issue = Issue(
            description=form.issue.data,
            reported_by=current_user.id,
            type='driver_report' if current_user.role == 'driver' else 'student_report'
        )
        db.session.add(issue)
        db.session.commit()
        flash('Issue reported successfully', 'success')
    return redirect(request.referrer)

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if form.new_password.data != form.confirm_password.data:
            flash('New passwords do not match', 'danger')
        elif current_user.check_password(form.current_password.data):
            current_user.set_password(form.new_password.data)
            db.session.commit()
            flash('Password updated successfully', 'success')
        else:
            flash('Current password is incorrect', 'danger')
    return redirect(request.referrer)

@app.route('/api/users/add', methods=['POST'])
@login_required
def add_user():
    if not current_user.role == 'admin':
        return jsonify({"status": "error", "message": "Unauthorized"}), 403
    
    data = request.get_json()
    if not data:
        return jsonify({"status": "error", "message": "No data provided"}), 400
    
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    role = data.get('role')
    
    if not all([username, email, password, role]):
        return jsonify({"status": "error", "message": "Missing required fields"}), 400
    
    if db.session.query(User).filter_by(username=username).first():
        return jsonify({"status": "error", "message": "Username already exists"}), 400
    
    if db.session.query(User).filter_by(email=email).first():
        return jsonify({"status": "error", "message": "Email already exists"}), 400
    
    try:
        new_user = User(
            username=username,
            email=email,
            role=role
        )
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        
        # Log the activity
        log = ActivityLog(action=f"Added new {role} user: {username}")
        db.session.add(log)
        db.session.commit()
        
        return jsonify({
            "status": "success",
            "message": f"User {username} added successfully",
            "user": {
                "id": new_user.id,
                "username": new_user.username,
                "email": new_user.email,
                "role": new_user.role
            }
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({"status": "error", "message": f"Failed to add user: {str(e)}"}), 500

@app.route('/api/users/delete', methods=['POST'])
@login_required
def delete_user():
    if not current_user.role == 'admin':
        return jsonify({"status": "error", "message": "Unauthorized"}), 403
    
    data = request.get_json()
    if not data:
        return jsonify({"status": "error", "message": "No data provided"}), 400
    
    user_id = data.get('user_id')
    if not user_id:
        return jsonify({"status": "error", "message": "Missing user_id"}), 400
    
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({"status": "error", "message": "User not found"}), 404
        
        # Prevent deleting the currently logged-in admin
        if user.id == current_user.id:
            return jsonify({"status": "error", "message": "Cannot delete your own account"}), 400
            
        # Log the activity before deleting
        log = ActivityLog(action=f"Deleted {user.role} user: {user.username}")
        
        # For safety, check if user is referenced anywhere before deletion
        has_dependencies = False
        
        # Check if user is a driver assigned to any buses
        if user.role == 'driver' and Bus.query.filter_by(driver_id=user.id).first():
            has_dependencies = True
            
        # Check if user has reported any issues
        if Issue.query.filter_by(reported_by=user.id).first():
            has_dependencies = True
            
        # Check if user has active notifications
        if Notification.query.filter_by(user_id=user.id).first():
            has_dependencies = True
            
        # If user has dependencies, handle accordingly (we'll just warn for now but proceed)
        username = user.username
        
        # Delete the user
        db.session.delete(user)
        db.session.add(log)
        db.session.commit()
        
        return jsonify({
            "status": "success",
            "message": f"User {username} deleted successfully",
            "has_dependencies": has_dependencies
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({"status": "error", "message": f"Failed to delete user: {str(e)}"}), 500

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

def create_sample_data():
    if User.query.first():
        return
    admin = User(username='admin', email='admin@example.com', role='admin')
    admin.set_password('admin123')
    driver1 = User(username='driver1', email='driver1@example.com', role='driver')
    driver1.set_password('driver123')
    student1 = User(username='student1', email='student1@example.com', role='student')
    student1.set_password('student123')
    db.session.add_all([admin, driver1, student1])
    
    bus1 = Bus(name='Bus #103', status='active', driver_id=driver1.id)
    bus2 = Bus(name='Bus #104', status='active')
    bus3 = Bus(name='Bus #105', status='maintenance')
    db.session.add_all([bus1, bus2, bus3])
    
    route1 = Route(name='Campus Loop', description='Circles the main campus')
    route2 = Route(name='Downtown Express', description='Express route to downtown')
    db.session.add_all([route1, route2])
    db.session.commit()
    
    stop1 = Stop(name='Main Gate', lat=40.7128, lng=-74.0060, route_id=route1.id)
    stop2 = Stop(name='Library', lat=40.7138, lng=-74.0070, route_id=route1.id)
    stop3 = Stop(name='Dormitory', lat=40.7148, lng=-74.0080, route_id=route1.id)
    stop4 = Stop(name='City Center', lat=40.7228, lng=-74.0160, route_id=route2.id)
    db.session.add_all([stop1, stop2, stop3, stop4])
    
    now = datetime.utcnow()
    schedule1 = Schedule(bus_id=bus1.id, route_id=route1.id, departure_time=now, arrival_time=now + timedelta(hours=1), status='in-progress')
    schedule2 = Schedule(bus_id=bus2.id, route_id=route2.id, departure_time=now + timedelta(hours=1), arrival_time=now + timedelta(hours=2), status='scheduled')
    db.session.add_all([schedule1, schedule2])
    db.session.commit()

if __name__ == '__main__':
    with app.app_context():
        try:
            # Create database if it doesn't exist
            connection = mysql.connector.connect(
                host='localhost',
                user='root',  # Replace with your MySQL username
                password='2004'  # Replace with your MySQL password
            )
            cursor = connection.cursor()
            cursor.execute("CREATE DATABASE IF NOT EXISTS bus_tracker")
            cursor.close()
            connection.close()
            
            # Create all tables
            db.create_all()
            create_sample_data()
        except Error as e:
            print(f"Error connecting to MySQL: {e}")
    
    # Run the app with both localhost and network access
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, allow_unsafe_werkzeug=True)