from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import Base, User
import bcrypt

DATABASE_URL = "mysql+mysqlconnector://root:password@localhost/dentalhcis"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base.metadata.create_all(bind=engine)  # Creates the database tables

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def add_admin_if_not_exists():
    db = SessionLocal()
    try:
        admin = db.query(User).filter(User.username == "admin").first()
        if not admin:
            password = "password"  # Use a strong password and consider using environment variables
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            new_admin = User(
                username='admin',
                email='admin@example.com',
                password_hash=hashed_password,
                role='admin'
            )
            db.add(new_admin)
            db.commit()
            print("Admin user created.")
        else:
            print("Admin user already exists.")
    except Exception as e:
        print(f"Error creating admin user: {e}")
    finally:
        db.close()

# Call the function to ensure an admin user is added if not already present
add_admin_if_not_exists()
