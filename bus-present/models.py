from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(UserMixin, db.Model):
    __tablename__ = 'users'  # Explicitly set the table name
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'admin' or 'driver'
    
    @property
    def is_admin(self):
        return self.role == 'admin'
    
    @property
    def is_driver(self):
        return self.role == 'driver'

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Bus(db.Model):
    __tablename__ = 'buses'  # Explicitly set table name
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(20), default='inactive')
    current_lat = db.Column(db.Float, nullable=True)
    current_lng = db.Column(db.Float, nullable=True)
    last_updated = db.Column(db.DateTime, nullable=True)
    driver_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    schedules = db.relationship('Schedule', backref='bus', lazy=True)
    driver = db.relationship('User', backref='bus', foreign_keys=[driver_id])

class Route(db.Model):
    __tablename__ = 'routes'  # Explicitly set table name
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    stops = db.relationship('Stop', backref='route', lazy=True)
    schedules = db.relationship('Schedule', backref='route', lazy=True)

class Stop(db.Model):
    __tablename__ = 'stops'  # Explicitly set table name
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    lat = db.Column(db.Float, nullable=False)
    lng = db.Column(db.Float, nullable=False)
    route_id = db.Column(db.Integer, db.ForeignKey('routes.id'), nullable=False)

class Schedule(db.Model):
    __tablename__ = 'schedules'  # Explicitly set table name
    id = db.Column(db.Integer, primary_key=True)
    bus_id = db.Column(db.Integer, db.ForeignKey('buses.id'), nullable=False)
    route_id = db.Column(db.Integer, db.ForeignKey('routes.id'), nullable=False)
    departure_time = db.Column(db.DateTime, nullable=False)
    arrival_time = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(20), default='scheduled')

class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(200))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Issue(db.Model):
    __tablename__ = 'issues'  # Explicitly set table name
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.Text, nullable=False)
    reported_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    type = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), default='Pending')
    urgency = db.Column(db.String(20), default='normal')
    reported_at = db.Column(db.DateTime, default=datetime.utcnow)
    reported_by_user = db.relationship('User', backref='reported_issues', foreign_keys=[reported_by])

class RouteRequest(db.Model):
    __tablename__ = 'route_requests'
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    request_type = db.Column(db.String(50), nullable=False)
    route_number = db.Column(db.String(50), nullable=True)
    details = db.Column(db.Text, nullable=False)
    reason = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='Pending', nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    student = db.relationship('User', backref='route_requests')

class Notification(db.Model):
    __tablename__ = 'notifications'
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.String(500), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    type = db.Column(db.String(50), default='general')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    read = db.Column(db.Boolean, default=False)
    recipient_type = db.Column(db.String(50), nullable=True)
    user = db.relationship('User', backref=db.backref('notifications', lazy=True))

    def __repr__(self):
        return f'<Notification {self.id}: {self.message[:30]}...>'

class RouteStop(db.Model):
    __tablename__ = 'route_stops'
    id = db.Column(db.Integer, primary_key=True)
    route_id = db.Column(db.Integer, db.ForeignKey('routes.id'), nullable=False)
    stop_id = db.Column(db.Integer, db.ForeignKey('stops.id'), nullable=False)
    sequence = db.Column(db.Integer, nullable=False)
    scheduled_time = db.Column(db.DateTime, nullable=True)
    route = db.relationship('Route', backref=db.backref('route_stops', lazy=True))
    stop = db.relationship('Stop', backref=db.backref('route_stops', lazy=True))