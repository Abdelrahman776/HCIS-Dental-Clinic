import io
from fastapi import FastAPI, Depends, File, HTTPException, UploadFile, status , Form
from sqlalchemy import Column, Integer, String, Date, Text, ForeignKey , Boolean, func
from sqlalchemy.orm import Session
from models import User , Patient , Appointment , Doctor , Bill , Payment , MedicalHistory
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
import stripe
import PyPDF2
from sqlalchemy.orm import Session

# Set your secret key. Remember to switch to your live secret key in production.
# See your keys here: https://dashboard.stripe.com/apikeys
stripe.api_key = 'sk_test_51PGLSz08Zs9MquJ9jqBzbXGMWraK3ZbUKsOr0Xya8hjZHggvSNy8RwXai7qRLqvThwib4y14Tw99pI6WJazp6GhI00BtA0BnI9'

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



class AppointmentCreate(BaseModel):
    patient_id: int
    patient_name: str
    doctor_id: int
    doctor_name: str
    scheduled_time: datetime
    notes: Optional[str] = None

class UserProfileResponse(BaseModel):
    id: int
    username: str
    email: EmailStr
    role: str
    full_name: Optional[str] = None
    dob: Optional[datetime] = None
    gender: Optional[str] = None
    address: Optional[str] = None
    phone: Optional[str] = None
    insurance_details: Optional[str] = None
    medical_history: Optional[str] = None
    dental_history: Optional[str] = None
    language_preference: Optional[str] = None

    class Config:
        arbitrary_types_allowed = True

class UserProfile(BaseModel):
    username: str
    email: str
    full_name: Optional[str] = None
    dob: Optional[datetime] = None
    gender: Optional[str] = None
    address: Optional[str] = None
    phone: Optional[str] = None
    role: str
class UserProfileUpdateRequest(BaseModel):
    full_name: Optional[str] = None
    dob: Optional[str] = None  # We will accept string and parse it to date
    gender: Optional[str] = None
    address: Optional[str] = None
    phone: Optional[str] = None

class UserUpdateModel(BaseModel):
    username: Optional[str] = None
    email: Optional[str] = None
    full_name: Optional[str] = None
    dob: Optional[datetime] = None
    gender: Optional[str] = None
    address: Optional[str] = None
    phone: Optional[str] = None

class CreateBill(BaseModel):
    patient_id: int
    amount_due: float
    due_date: datetime
    status: Optional[str] = 'unpaid'  # Set 'unpaid' as default status




class ProcessPayment(BaseModel):
    bill_id: int
    amount_paid: float
    payment_method: str


class BillResponseModel(BaseModel):
    id: int
    patient_id: int
    amount_due: float
    due_date: datetime
    status: str






class PaymentResponse(BaseModel):
    id: int
    bill_id: int
    amount: float
    payment_method: str
    status: str

class PatientResponse(BaseModel):
    id: int
    full_name: str
    dob: datetime
    gender: str
    address: str
    phone: str
    email: str
    insurance_details: Optional[str] = None
    medical_history: Optional[str] = None
    dental_history: Optional[str] = None
    language_preference: Optional[str] = None


class DoctorResponse(BaseModel):
    id: int
    username: str
    email: str
    role: str
    full_name: Optional[str] = None
    dob: Optional[datetime] = None
    gender: Optional[str] = None
    address: Optional[str] = None
    phone: Optional[str] = None

    class Config:
        arbitrary_types_allowed = True



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

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

from fastapi import HTTPException, Form, Depends
from pydantic import EmailStr
from sqlalchemy.orm import Session
from datetime import datetime
import bcrypt
from models import User, Patient, Doctor  # Ensure these are imported or defined in your context
from sqlalchemy.orm import joinedload
from fastapi import HTTPException, Form, Depends
from pydantic import EmailStr
from sqlalchemy.orm import Session
from datetime import datetime
import bcrypt
from models import User, Patient, Doctor  # Ensure these are imported or defined in your context
from sqlalchemy.exc import IntegrityError

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

    # Check if the email or username already exists in the database
    existing_user = db.query(User).filter((User.email == email) | (User.username == username)).first()
    if existing_user:
        if existing_user.email == email:
            raise HTTPException(status_code=400, detail="Email already in use")
        elif existing_user.username == username:
            raise HTTPException(status_code=400, detail="Username already in use")

    try:
        dob = datetime.strptime(dob_str, "%Y-%m-%d")  # Parse the date string
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid date format")

    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    # Create a new user instance
    new_user = User(username=username, email=email, password_hash=hashed_password, role=role)

    try:
        # Start the transaction
        db.add(new_user)
        db.flush()  # Flush here to catch any integrity errors early

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
        elif role == "doctor":
            new_doctor = Doctor(
                user_id=new_user.id,
                full_name=full_name,
                dob=dob,
                gender=gender,
                address=address,
                phone=phone
            )
            db.add(new_doctor)

        db.commit()  # Commit the transaction

    except Exception as e:
        db.rollback()  # Roll back the transaction on error
        raise HTTPException(status_code=500, detail="Failed to register user")

    # Assuming send_email is defined elsewhere
    body = f"Hello {full_name},\n\nWelcome to our service! We are excited to have you on board."
    send_email("Welcome to Our Service", email, body)

    return {
        "message": "Registration successful, and a welcome email has been sent.",
        "username": username,
        "email": email,
        "role": role
    }

@app.post("/login/", response_model=LoginResponse)
def login_user(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if user:
        logging.info(f"User found: {user.username}")
        if bcrypt.checkpw(form_data.password.encode(), user.password_hash.encode()):
            logging.info("Password matched")
            access_token = create_access_token(data={"sub": user.username, "user_id": user.id, "role": user.role}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
            return LoginResponse(access_token=access_token, token_type="bearer", user_id=user.id, role=user.role)
        else:
            logging.error("Password did not match")
    else:
        logging.error("User not found")
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
    print("Token:", token)
    print("New Password:", new_password)

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
            return PasswordResetResponse(message="Password reset successful", reset_token=token)  # Include reset_token in the response
        else:
            raise HTTPException(status_code=404, detail="User not found")
    except JWTError as e:
        raise HTTPException(status_code=403, detail="Invalid token")
    
async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = payload.get("user_id")
        if user_id is None:
            raise HTTPException(status_code=403, detail="Invalid authentication credentials")
        user = db.query(User).filter(User.id == user_id).first()
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

from fastapi import HTTPException, Depends
from sqlalchemy.orm import Session
import logging
@app.post("/appointments/", response_model=AppointmentCreate)
def schedule_appointment(
    appointment_data: AppointmentCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.role != "patient":
        raise HTTPException(status_code=403, detail="Only patients can schedule appointments.")

    doctor = db.query(Doctor).filter(Doctor.id == appointment_data.doctor_id).first()
    if not doctor:
        raise HTTPException(status_code=404, detail="Doctor not found")

    patient = db.query(Patient).filter(Patient.id == appointment_data.patient_id).first()
    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found")

    new_appointment = Appointment(
        patient_id=appointment_data.patient_id,
        doctor_id=appointment_data.doctor_id,
        scheduled_time=appointment_data.scheduled_time,
        status='scheduled',
        notes=appointment_data.notes,
        patient_name=patient.full_name,
        doctor_name=doctor.full_name
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
    return db.query(Appointment).filter(Appointment.doctor_id == doctor_id).all() # Combine the basic user profile with role-specific details



@app.get("/doctors/", response_model=List[DoctorResponse])
def list_doctors(db: Session = Depends(get_db)):
    try:
        doctors = db.query(Doctor).options(joinedload(Doctor.user)).all()
        if not doctors:
            raise HTTPException(status_code=404, detail="No doctors found")

        result = []
        for doctor in doctors:
            doctor_data = {
                "id": doctor.id,
                "username": doctor.user.username,
                "email": doctor.user.email,
                "role": doctor.user.role,
                "full_name": doctor.full_name,
                "dob": doctor.dob,
                "gender": doctor.gender,
                "address": doctor.address,
                "phone": doctor.phone
            }
            result.append(doctor_data)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
@app.put("/users/me/", response_model=UserProfile)
async def update_user_profile(update_data: UserProfileUpdateRequest, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    user_data = update_data.dict(exclude_unset=True)
    for key, value in user_data.items():
        if key == 'dob' and value:
            value = datetime.strptime(value, "%Y-%m-%d")  # Parse string to datetime object
        setattr(current_user, key, value)
    
    db.add(current_user)
    db.commit()
    db.refresh(current_user)
    return current_user
def mock_payment_gateway(amount, payment_method):
    print(f"Mock payment of ${amount} using {payment_method}")
    return True  # Simulate a successful payment
@app.post("/bills/", response_model=BillResponseModel)
def create_bill(bill: CreateBill, db: Session = Depends(get_db)):
    # Create a new bill with default status if not provided
    new_bill = Bill(
        patient_id=bill.patient_id,
        amount_due=bill.amount_due,
        due_date=bill.due_date,
        status=bill.status if bill.status else 'unpaid'
    )
    db.add(new_bill)
    db.commit()
    db.refresh(new_bill)
    return new_bill


@app.post("/payments/", response_model=PaymentResponse)
def process_payment(payment_data: ProcessPayment, db: Session = Depends(get_db)):
    bill = db.query(Bill).filter(Bill.id == payment_data.bill_id).first()
    if not bill:
        raise HTTPException(status_code=404, detail="Bill not found")
    if bill.status == 'paid':
        raise HTTPException(status_code=400, detail="This bill has already been paid.")

    # Attempt to charge the customer using Stripe
    try:
        charge = stripe.Charge.create(
            amount=int(payment_data.amount_paid * 100),  # amount in cents
            currency="usd",
            source=payment_data.payment_method,  # obtained with Stripe.js
            description=f"Charge for bill {bill.id}"
        )
        bill.status = 'paid'
        db.commit()

        new_payment = Payment(
            bill_id=bill.id,
            amount=payment_data.amount_paid,
            payment_method=payment_data.payment_method,
            status='paid' if charge['paid'] else 'failed'
        )
        db.add(new_payment)
        db.commit()
        db.refresh(new_payment)
        return new_payment
    except stripe.error.StripeError as e:
        # Handle the case where the charge fails
        raise HTTPException(status_code=400, detail=str(e))





@app.get("/user_info", response_model=UserProfileResponse)
async def get_user_info(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    user_data = {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "role": current_user.role
    }
    
    if current_user.role == "patient":
        patient = db.query(Patient).filter(Patient.user_id == current_user.id).first()
        if not patient:
            raise HTTPException(status_code=404, detail="Patient not found")
        user_data.update({
            "full_name": patient.full_name,
            "dob": patient.dob,
            "gender": patient.gender,
            "address": patient.address,
            "phone": patient.phone,
            "insurance_details": patient.insurance_details,
            "medical_history": patient.medical_history,
            "dental_history": patient.dental_history,
            "language_preference": patient.language_preference
        })
    
    elif current_user.role == "doctor":
        doctor = db.query(Doctor).filter(Doctor.user_id == current_user.id).first()
        if not doctor:
            raise HTTPException(status_code=404, detail="Doctor not found")
        user_data.update({
            "full_name": doctor.full_name,
            "dob": doctor.dob,
            "gender": doctor.gender,
            "address": doctor.address,
            "phone": doctor.phone
        })
    
    return user_data


@app.delete("/users/{user_id}")
def delete_user(user_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    
    
    user_to_delete = db.query(User).filter(User.id == user_id).first()
    if not user_to_delete:
        raise HTTPException(status_code=404, detail="User not found")
    
    db.delete(user_to_delete)
    db.commit()
    return {"message": "User successfully deleted"}


@app.get("/users")
def view_all_users(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    
    users = db.query(User).all()
    return users

@app.get("/patients")
def view_all_patients(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    
    patients = db.query(Patient).all()
    return patients

@app.get("/staff")
def view_all_staff(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if current_user.role != 'admin':
        raise HTTPException(status_code=403, detail="Access denied: Admin privileges required.")
    
    staff = db.query(staff).all()
    return staff

@app.put("/users/{user_id}")
def update_user(user_id: int, user_update: UserUpdateModel, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if current_user.role != 'admin':
        raise HTTPException(status_code=403, detail="Access denied: Admin privileges required.")

    user_to_update = db.query(User).filter(User.id == user_id).first()
    if not user_to_update:
        raise HTTPException(status_code=404, detail="User not found")

    user_data = user_update.dict(exclude_unset=True)
    for key, value in user_data.items():
        if hasattr(user_to_update, key):
            setattr(user_to_update, key, value)

    db.commit()
    return {"message": "User data successfully updated", "user": user_to_update.username}  # Returning username for confirmation

@app.get("/clinical-performance/")
def clinical_performance(db: Session = Depends(get_db)):
    completed_appointments = db.query(Appointment).filter(Appointment.status == 'completed').count()
    canceled_appointments = db.query(Appointment).filter(Appointment.status == 'cancelled').count()
    
    # Calculate most/least used services based on appointment data
    # Replace 'service_field' with the actual field in your Appointment model representing services
    most_used_service = db.query(Appointment.service_field).group_by(Appointment.service_field).order_by(func.count().desc()).first()
    least_used_service = db.query(Appointment.service_field).group_by(Appointment.service_field).order_by(func.count()).first()
    
    return {
        "completed_appointments": completed_appointments,
        "canceled_appointments": canceled_appointments,
        "most_used_service": most_used_service,
        "least_used_service": least_used_service
    }

@app.get("/patient-statistics/")
def patient_statistics(db: Session = Depends(get_db)):
    gender_distribution = db.query(Patient.gender, func.count()).group_by(Patient.gender).all()
    # Calculate age distribution based on date of birth
    # Replace 'dob' with the actual field representing date of birth in your Patient model
    age_distribution = db.query(func.floor(func.datediff(datetime.now(), Patient.dob) / 365), func.count()).group_by(func.floor(func.datediff(datetime.now(), Patient.dob) / 365)).all()
    total_patients = db.query(Patient).count()
    
    return {
        "gender_distribution": gender_distribution,
        "age_distribution": age_distribution,
        "total_patients": total_patients
    }

@app.get("/financial-insights/")
def financial_insights(db: Session = Depends(get_db)):
    total_amount_due = db.query(func.sum(Bill.amount_due)).scalar()
    total_amount_paid = db.query(func.sum(Payment.amount)).scalar()
    total_doctors = db.query(Doctor).count()
    total_patients = db.query(Patient).count()
    
    return {
        "total_amount_due": total_amount_due,
        "total_amount_paid": total_amount_paid,
        "total_doctors": total_doctors,
        "total_patients": total_patients
    }




@app.post("/medical-history/{patient_id}/")
async def upload_medical_history(patient_id: int, pdf_file: UploadFile = File(...), db: Session = Depends(get_db)):
    # Check if the current user has permission to upload medical records
    # You might want to implement authorization logic here

    # Read the PDF file
    pdf_content = await pdf_file.read()

    # Extract text from the PDF
    pdf_text = extract_text_from_pdf(pdf_content)

    # Parse the extracted text to extract medical history information
    medical_history_data = parse_medical_history_text(pdf_text)

    # Store the medical history information in the database
    medical_history = MedicalHistory(patient_id=patient_id, **medical_history_data)
    db.add(medical_history)
    db.commit()

    return {"detail": "Medical history uploaded successfully"}

def extract_text_from_pdf(pdf_content: bytes) -> str:
    pdf_reader = PyPDF2.PdfFileReader(io.BytesIO(pdf_content))
    text = ""
    for page_num in range(pdf_reader.numPages):
        text += pdf_reader.getPage(page_num).extractText()
    return text

def parse_medical_history_text(text: str) -> dict:
    # Implement your logic to parse the text and extract medical history information
    # This can be done using regex or other text processing techniques
    # In this example, we assume a simple parsing where each line contains a field and its corresponding value
    medical_history_data = {}
    lines = text.split("\n")
    for line in lines:
        if ":" in line:
            field, value = line.split(":", 1)
            medical_history_data[field.strip().lower().replace(" ", "_")] = value.strip()
    return medical_history_data