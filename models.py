from sqlalchemy import Column, Integer, String
from sqlalchemy.orm import declarative_base

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(255), unique=True, index=True)  # Maintain existing attributes
    password_hash = Column(String(255))
    role = Column(String(255))
    email = Column(String(255), unique=True, index=True)  # Add email attribute
