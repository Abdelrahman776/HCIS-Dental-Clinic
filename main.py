from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session
from models import User
from database import get_db
import bcrypt
from pydantic import BaseModel

app = FastAPI()

class RegistrationResponse(BaseModel):
    message: str
    username: str
    email: str
    role: str

class LoginResponse(BaseModel):
    message: str

class RecoveryResponse(BaseModel):
    message: str

@app.post("/register/", response_model=RegistrationResponse)
def register_user(username: str, email: str, password: str, db: Session = Depends(get_db)):
    # Normalize email and check for the '-d' suffix
    email = email.lower()
    if email.endswith("-d"):
        role = "doctor"
        email = email[:-2]  # Remove the "-d" suffix from the email
    else:
        role = "patient"

    # Check if email or username already exists
    if db.query(User).filter((User.username == username) | (User.email == email)).first():
        raise HTTPException(status_code=400, detail="Username or email already in use")

    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    new_user = User(username=username, email=email, password_hash=hashed_password, role=role)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return RegistrationResponse(message="User registered successfully", username=username, email=email, role=role)
@app.post("/login/", response_model=LoginResponse)
def login_user(username: str, password: str, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == username).first()
    if db_user and bcrypt.checkpw(password.encode(), db_user.password_hash.encode()):
        return LoginResponse(message="Login successful")
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

@app.post("/password-recovery/", response_model=RecoveryResponse)
def request_password_recovery(username: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    send_reset_email(user.email)
    return RecoveryResponse(message="If your account exists, a password reset link has been sent to your email.")

def send_reset_email(email: str):
    # This function should integrate with an actual email service provider.
    print(f"Reset link would be sent to {email}")
