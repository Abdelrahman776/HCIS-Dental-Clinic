from sqlalchemy import Column, Integer, String, Date, Text, ForeignKey , Boolean
from sqlalchemy.orm import relationship, declarative_base


Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(255), unique=True, index=True)
    password_hash = Column(String(255))
    role = Column(String(255))
    email = Column(String(255), unique=True, index=True)
    is_active = Column(Boolean, default=False)
    patients = relationship("Patient", back_populates="user")
 
class Patient(Base):
    __tablename__ = 'patients'
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    full_name = Column(String(255))
    dob = Column(Date)
    gender = Column(String(50))
    address = Column(String(255))
    phone = Column(String(50))
    email = Column(String(255))
    insurance_details = Column(String(255))
    medical_history = Column(Text)
    dental_history = Column(Text)
    language_preference = Column(String(50))
    user = relationship("User", back_populates="patients")


  # Assuming role is needed at registration, adjust if not necessary
