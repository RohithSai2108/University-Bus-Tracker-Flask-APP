from flask import render_template
from flask_login import login_required  # Add this import
from .models import User, Bus, Schedule
from . import app  # Import the app object
from collections import defaultdict

@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    buses = Bus.query.all()
    drivers = {user.id: user for user in User.query.filter_by(role='driver').all()}
    schedules = Schedule.query.all()
    schedules_by_bus = defaultdict(lambda: None)
    for schedule in schedules:
        schedules_by_bus[schedule.bus_id] = schedule

    return render_template(
        'admin_dashboard.html',
        buses=buses,
        drivers=drivers,
        schedules=schedules,
        schedules_by_bus=schedules_by_bus,
        User=User,  # Pass the User model to the template
        # ...existing context variables...
    )
