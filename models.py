from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, Date, Text, Enum, DateTime , Float
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
    appointments = relationship("Appointment", back_populates="doctor", foreign_keys="[Appointment.doctor_id]")

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
    medical_history = Column(Text)
    dental_history = Column(Text)
    language_preference = Column(String(50))
    appointments = relationship("Appointment", back_populates="patient", foreign_keys="[Appointment.patient_id]")

class Doctor(Base):
    __tablename__ = 'doctors'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), unique=True)
    specialization = Column(String(255))
    consultation_hours = Column(String(255))
    user = relationship("User", back_populates="doctor")

class Appointment(Base):
    __tablename__ = 'appointments'
    id = Column(Integer, primary_key=True)
    patient_id = Column(Integer, ForeignKey('patients.id'))
    doctor_id = Column(Integer, ForeignKey('users.id'))
    scheduled_time = Column(DateTime)
    status = Column(Enum('scheduled', 'completed', 'cancelled', name='status_types'))
    notes = Column(String, nullable=True)
    # Relationships to User and Patient
    patient = relationship("Patient", back_populates="appointments")
    doctor = relationship("User", back_populates="appointments")



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

