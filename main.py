from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session
from models import User
from database import get_db
import bcrypt
from pydantic import BaseModel
from jose import jwt, JWTError
from datetime import datetime, timedelta
from fastapi.security import OAuth2PasswordBearer

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

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if not username:
            raise HTTPException(status_code=403, detail="Invalid authentication credentials")
        # Fetch user from database or cache
        return username  # You may want to return the entire user object here
    except JWTError as e:
        raise HTTPException(status_code=403, detail="Invalid authentication token")

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
    user = db.query(User).filter(User.username == username).first()
    if user and bcrypt.checkpw(password.encode(), user.password_hash.encode()):
        access_token = create_access_token(data={"sub": user.username}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
        return {"access_token": access_token, "token_type": "bearer"}
    else:
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

@app.get("/users/me/")
def read_users_me(db: Session = Depends(get_db), current_user: str = Depends(get_current_user)):
    # Fetch the user object based on the username and return it
    user = db.query(User).filter(User.username == current_user).first()
    if user:
        return user
    else:
        raise HTTPException(status_code=404, detail="User not found")
