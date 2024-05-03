from sqlalchemy import Column, Integer, String, Date, Text, ForeignKey , Boolean
from sqlalchemy.orm import relationship, declarative_base


Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(255), unique=True)
    email = Column(String(255), unique=True)
    password_hash = Column(String(255))
    role = Column(String(50))

class Patient(Base):
    __tablename__ = 'patients'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    full_name = Column(String(255))
    dob = Column(Date)
    gender = Column(String(50))
    address = Column(String(255))
    phone = Column(String(50))
    insurance_details = Column(String(255))
    medical_history = Column(Text)
    dental_history = Column(Text)
    language_preference = Column(String(50))
    user = relationship("User", back_populates="patients")

User.patients = relationship("Patient", back_populates="user", uselist=False)
