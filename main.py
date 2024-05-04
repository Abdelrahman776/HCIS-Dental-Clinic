from fastapi import FastAPI, Depends, HTTPException, status , Form
from sqlalchemy import Column, Integer, String, Date, Text, ForeignKey , Boolean
from sqlalchemy.orm import Session
from models import User , Patient , Appointment , Doctor
from database import get_db
import bcrypt
from pydantic import BaseModel , EmailStr
from jose import jwt, JWTError
from datetime import datetime, timedelta
from fastapi.security import OAuth2PasswordBearer , OAuth2PasswordRequestForm
from fastapi.responses import RedirectResponse
from typing import Optional , List
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

app = FastAPI()

SECRET_KEY = "big_secret"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 90

class RegistrationResponse(BaseModel):
    message: str
    username: str
    email: str
    role: str

class RecoveryResponse(BaseModel):
    message: str

class LoginResponse(BaseModel):
    access_token: str
    token_type: str
    user_id: int
    role: str  # Add role here

class PasswordResetRequest(BaseModel):
    email: str

class PasswordResetResponse(BaseModel):
    message: str
    reset_token: str 

class PatientResponse(BaseModel):
    id: int
    full_name: str
    dob: datetime
    gender: str
    address: str
    phone: str
    insurance_details: Optional[str] = None
    medical_history: Optional[str] = None
    dental_history: Optional[str] = None
    language_preference: Optional[str] = None

class AppointmentCreate(BaseModel):
    patient_id: int
    doctor_id: int
    scheduled_time: datetime
    notes: Optional[str] = None
class DoctorResponse(BaseModel):
    id: int
    username: str
    email: str
    role: str  # This assumes role is a field in your User model

    # Add other fields that might be relevant for the patient to choose a doctor.

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

@app.get("/")
def root():
    return RedirectResponse(url="/docs")

def send_email(subject, receiver_email, body, smtp_server="smtp.office365.com", smtp_port=587, sender_email="dentalhcis@outlook.com", password="passwordpassword123"):
    try:
        message = MIMEMultipart()
        message["From"] = sender_email
        message["To"] = receiver_email
        message["Subject"] = subject
        message.attach(MIMEText(body, "plain"))

        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()  # Secure the connection
        server.login(sender_email, password)
        server.sendmail(sender_email, receiver_email, message.as_string())
        server.quit()
    except Exception as e:
        print(f"Failed to send email: {e}")

def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

@app.post("/register/", response_model=RegistrationResponse)
def register_user(
    username: str = Form(...),
    email: EmailStr = Form(...),
    password: str = Form(...),
    full_name: str = Form(...),
    dob_str: str = Form(...),
    gender: str = Form(...),
    address: str = Form(...),
    phone: str = Form(...),
    db: Session = Depends(get_db)
):
    email = email.lower()
    role = "doctor" if email.endswith("-d") else "patient"
    if email.endswith("-d"):
        email = email[:-2]

    if db.query(User).filter(User.email == email).first():
        raise HTTPException(status_code=400, detail="Email already in use")
    
    try:
        dob = datetime.strptime(dob_str, "%Y-%m-%d")  # Parse the date string
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid date format")

    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    new_user = User(username=username, email=email, password_hash=hashed_password, role=role)
    db.add(new_user)
    db.commit()
    if role == "patient":
        new_patient = Patient(
            user_id=new_user.id,
            full_name=full_name,
            dob=dob,
            gender=gender,
            address=address,
            phone=phone
        )
        db.add(new_patient)
        db.commit()

    body = f"Hello {full_name},\n\nWelcome to our service! We are excited to have you on board."
    send_email("Welcome to Our Service", email, body)

    return RegistrationResponse(
        message="Registration successful, and a welcome email has been sent.",
        username=username,
        email=email,
        role=role
    )

@app.post("/login/", response_model=LoginResponse)
def login_user(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if user and bcrypt.checkpw(form_data.password.encode(), user.password_hash.encode()):
        access_token = create_access_token(data={"sub": user.username, "user_id": user.id, "role": user.role}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
        return LoginResponse(access_token=access_token, token_type="bearer", user_id=user.id, role=user.role)
    else:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")


@app.post("/forgot-password/", response_model=PasswordResetResponse)
def forgot_password(request: PasswordResetRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == request.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    reset_token = create_access_token({"sub": user.username}, timedelta(minutes=15))
    
    send_password_reset_email(user.email, user.username, reset_token)

    return PasswordResetResponse(
        message="Password reset email sent successfully. Use the token to reset your password.",
        reset_token=reset_token
    )

def send_password_reset_email(email: str, username: str, token: str):
    try:
        reset_link = f"http://yourfrontenddomain.com/reset-password?token={token}"
        subject = "Password Reset Request"
        body = f"Hello {username},\n\nPlease follow this link to reset your password: {reset_link}\n\nIf you did not request this, please ignore this email."
        send_email(subject, email, body)
    except Exception as e:
        print(f"Failed to send password reset email: {e}")
        raise HTTPException(status_code=500, detail="Failed to send password reset email.")

@app.post("/reset-password/", response_model=PasswordResetResponse)
def reset_password(token: str, new_password: str, db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if not username:
            raise HTTPException(status_code=403, detail="Invalid token")
        
        user = db.query(User).filter(User.username == username).first()
        if user:
            hashed_password = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt())
            user.password_hash = hashed_password
            db.commit()
            return PasswordResetResponse(message="Password reset successful")
        else:
            raise HTTPException(status_code=404, detail="User not found")
    except JWTError as e:
        raise HTTPException(status_code=403, detail="Invalid token")
    
async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=403, detail="Invalid authentication credentials")
        user = db.query(User).filter(User.username == username).first()
        if user is None:
            raise HTTPException(status_code=403, detail="User not found")
        return user
    except JWTError:
        raise HTTPException(status_code=403, detail="Invalid authentication token")

@app.get("/patients/{user_id}/", response_model=PatientResponse)
async def get_patient_data(user_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    patient = db.query(Patient).filter(Patient.user_id == user_id).first()
    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found")

    if current_user.role not in ['doctor', 'admin'] and current_user.id != user_id:
        raise HTTPException(status_code=403, detail="Not authorized to access patient data")

    return patient

@app.post("/appointments/", response_model=AppointmentCreate)
def schedule_appointment(
    appointment_data: AppointmentCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Ensure current_user is a patient
    if current_user.role != "patient":
        raise HTTPException(status_code=403, detail="Only patients can schedule appointments.")

    # Ensure the doctor exists
    doctor = db.query(Doctor).filter(Doctor.id == appointment_data.doctor_id).first()
    if not doctor:
        raise HTTPException(status_code=404, detail="Doctor not found")

    # Create the appointment
    new_appointment = Appointment(
        patient_id=current_user.id,  # Use the logged-in patient's ID
        doctor_id=appointment_data.doctor_id,
        scheduled_time=appointment_data.scheduled_time,
        status='scheduled',
        notes=appointment_data.notes
    )
    db.add(new_appointment)
    db.commit()
    return new_appointment


@app.put("/appointments/{appointment_id}/", response_model=AppointmentCreate)
def update_appointment(appointment_id: int, appointment: AppointmentCreate, db: Session = Depends(get_db)):
    db_appointment = db.query(Appointment).filter(Appointment.id == appointment_id).first()
    if not db_appointment:
        raise HTTPException(status_code=404, detail="Appointment not found")
    
    db_appointment.scheduled_time = appointment.scheduled_time
    db_appointment.notes = appointment.notes
    db.commit()
    return db_appointment

@app.delete("/appointments/{appointment_id}/")
def cancel_appointment(appointment_id: int, db: Session = Depends(get_db)):
    db_appointment = db.query(Appointment).filter(Appointment.id == appointment_id).first()
    if not db_appointment:
        raise HTTPException(status_code=404, detail="Appointment not found")
    
    db_appointment.status = 'cancelled'
    db.commit()
    return {"message": "Appointment cancelled successfully"}

@app.get("/appointments/", response_model=List[AppointmentCreate])
def read_appointments(db: Session = Depends(get_db)):
    return db.query(Appointment).all()

@app.get("/appointments/patient/{patient_id}/", response_model=List[AppointmentCreate])
def read_patient_appointments(patient_id: int, db: Session = Depends(get_db)):
    return db.query(Appointment).filter(Appointment.patient_id == patient_id).all()

@app.get("/appointments/doctor/{doctor_id}/", response_model=List[AppointmentCreate])
def read_doctor_appointments(doctor_id: int, db: Session = Depends(get_db)):
    return db.query(Appointment).filter(Appointment.doctor_id == doctor_id).all()

@app.get("/myinfo/")
def get_my_info(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.role == 'patient':
        return db.query(Patient).filter(Patient.user_id == current_user.id).first()
    elif current_user.role == 'doctor':
        return db.query(Doctor).filter(Doctor.user_id == current_user.id).first()
    else:
        raise HTTPException(status_code=404, detail="User info not available")
@app.get("/doctors/", response_model=List[DoctorResponse])
def list_doctors(db: Session = Depends(get_db)):
    try:
        doctors = db.query(User).filter(User.role == 'doctor').all()
        if not doctors:
            raise HTTPException(status_code=404, detail="No doctors found")
        return doctors
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
