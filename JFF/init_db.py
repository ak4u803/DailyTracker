from app import app, db, User
from werkzeug.security import generate_password_hash
from datetime import datetime
import os

def init_db():
    with app.app_context():
        # Drop all tables if they exist
        db.drop_all()
        # Create all database tables
        db.create_all()
        print("Database tables created successfully!")

def create_admin(username='admin', email='admin@example.com', password='admin123'):
    with app.app_context():
        # Check if admin already exists
        if User.query.filter_by(username=username).first():
            print(f"Admin user '{username}' already exists!")
            return False
            
        # Create admin user
        admin = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(
                password,
                method='pbkdf2:sha256',
                salt_length=16
            ),
            is_admin=True,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        
        db.session.add(admin)
        db.session.commit()
        print(f"Admin user '{username}' created successfully!")
        print(f"Username: {username}")
        print(f"Password: {password}")
        print("IMPORTANT: Change this password after first login!")
        return True

def main():
    import argparse
    
    # Ensure the instance folder exists
    os.makedirs('instance', exist_ok=True)
    
    parser = argparse.ArgumentParser(description='Initialize the database')
    parser.add_argument('--create-admin', action='store_true', help='Create an admin user')
    parser.add_argument('--username', default='admin', help='Admin username (default: admin)')
    parser.add_argument('--email', default='admin@example.com', help='Admin email')
    parser.add_argument('--password', default='admin123', help='Admin password (default: admin123)')
    
    args = parser.parse_args()
    
    try:
        # Initialize the database
        print("Initializing database...")
        init_db()
        
        # Create admin user if requested
        if args.create_admin:
            create_admin(args.username, args.email, args.password)
            
        print("Database setup completed successfully!")
    except Exception as e:
        print(f"Error setting up database: {str(e)}")
        if hasattr(e, '__traceback__'):
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    main()
