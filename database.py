from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import Base

DATABASE_URL = "mysql+mysqlconnector://root:password@localhost/dentalhcis"

engine = create_engine(DATABASE_URL , echo=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base.metadata.create_all(bind=engine)  # Creates the database tables

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
