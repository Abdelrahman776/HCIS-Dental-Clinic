from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, Date, Text, Enum, DateTime, Float
from sqlalchemy.orm import declarative_base, relationship, sessionmaker

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(255), unique=True)
    password_hash = Column(String(255))
    role = Column(String(50))
    email = Column(String(255), unique=True)
    patients = relationship("Patient", back_populates="user")
    doctor = relationship("Doctor", back_populates="user", uselist=False)

class Doctor(Base):
    __tablename__ = 'doctors'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), unique=True)
    full_name = Column(String(255))
    dob = Column(Date)
    gender = Column(String(50))
    address = Column(String(255))
    phone = Column(String(50))
    user = relationship("User", back_populates="doctor")
    appointments = relationship("Appointment", back_populates="doctor")

class Patient(Base):
    __tablename__ = 'patients'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    user = relationship("User", back_populates="patients")
    full_name = Column(String(255))
    dob = Column(Date)
    gender = Column(String(50))
    address = Column(String(255))
    phone = Column(String(50))
    insurance_details = Column(String(255))
    appointments = relationship("Appointment", back_populates="patient")
    medical_history = relationship('MedicalHistory', back_populates='patient', uselist=False)

class Appointment(Base):
    __tablename__ = 'appointments'
    id = Column(Integer, primary_key=True)
    patient_id = Column(Integer, ForeignKey('patients.id'))
    doctor_id = Column(Integer, ForeignKey('doctors.id'))
    scheduled_time = Column(DateTime)
    status = Column(Enum('scheduled', 'completed', 'cancelled', name='status_types'))
    notes = Column(String(255), nullable=True)
    patient = relationship("Patient", back_populates="appointments")
    doctor = relationship("Doctor", back_populates="appointments")
class MedicalHistory(Base):
    __tablename__ = 'medical_history'
    id = Column(Integer, primary_key=True)
    patient_id = Column(Integer, ForeignKey('patients.id'))
    allergies = Column(Text)
    medications = Column(Text)
    diagnosis = Column(Text)
    lab_results = Column(Text)
    imaging_results = Column(Text)
    consultation_notes = Column(Text)
    patient = relationship('Patient', back_populates='medical_history')

class Bill(Base):
    __tablename__ = 'bills'
    id = Column(Integer, primary_key=True)
    patient_id = Column(Integer, ForeignKey('patients.id'))
    amount_due = Column(Float)
    due_date = Column(DateTime)
    status = Column(String(255), default='unpaid')
    payments = relationship('Payment', back_populates='bill')

class Payment(Base):
    __tablename__ = 'payments'
    id = Column(Integer, primary_key=True)
    bill_id = Column(Integer, ForeignKey('bills.id'))
    amount = Column(Float)
    payment_method = Column(String(255))
    bill = relationship('Bill', back_populates='payments')
