from app import app, db
from models import User, Bus, Route, Stop, Schedule, Issue, ActivityLog
from datetime import datetime, timedelta

def init_db():
    with app.app_context():
        # Drop all tables
        db.drop_all()
        # Create all tables
        db.create_all()
        
        print("Creating sample data...")
        # Create sample users
        admin = User(username='admin', email='admin@example.com', role='admin')
        admin.set_password('admin123')
        
        driver1 = User(username='driver1', email='driver1@example.com', role='driver')
        driver1.set_password('driver123')
        
        student1 = User(username='student1', email='student1@example.com', role='student')
        student1.set_password('student123')
        
        db.session.add_all([admin, driver1, student1])
        db.session.commit()
        
        # Create sample buses
        bus1 = Bus(name='Bus #103', status='active', driver_id=2)
        bus2 = Bus(name='Bus #104', status='active')
        bus3 = Bus(name='Bus #105', status='maintenance')
        
        db.session.add_all([bus1, bus2, bus3])
        
        # Create sample routes
        route1 = Route(name='Campus Loop', description='Circles the main campus')
        route2 = Route(name='Downtown Express', description='Express route to downtown')
        
        db.session.add_all([route1, route2])
        db.session.commit()
        
        # Create sample stops
        stops = [
            Stop(name='Main Gate', lat=40.7128, lng=-74.0060, route_id=1),
            Stop(name='Library', lat=40.7138, lng=-74.0070, route_id=1),
            Stop(name='Dormitory', lat=40.7148, lng=-74.0080, route_id=1),
            Stop(name='City Center', lat=40.7228, lng=-74.0160, route_id=2)
        ]
        db.session.add_all(stops)
        
        # Create sample schedules
        now = datetime.utcnow()
        schedules = [
            Schedule(
                bus_id=1,
                route_id=1,
                departure_time=now + timedelta(minutes=30),
                arrival_time=now + timedelta(hours=1),
                status='scheduled'
            ),
            Schedule(
                bus_id=2,
                route_id=2,
                departure_time=now + timedelta(hours=1),
                arrival_time=now + timedelta(hours=2),
                status='scheduled'
            )
        ]
        db.session.add_all(schedules)
        db.session.commit()
        print("Sample data created successfully!")

if __name__ == '__main__':
    init_db()
