from fastapi import FastAPI, Depends, HTTPException, status , Form
from sqlalchemy.orm import Session
from models import User
from database import get_db
import bcrypt
from pydantic import BaseModel , EmailStr
from jose import jwt, JWTError
from datetime import datetime, timedelta
from fastapi.security import OAuth2PasswordBearer , OAuth2PasswordRequestForm
from fastapi.responses import RedirectResponse
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
    is_active: bool

class RecoveryResponse(BaseModel):
    message: str

class LoginResponse(BaseModel):
    access_token: str
    token_type: str

class PasswordResetRequest(BaseModel):
    email: str

class PasswordResetResponse(BaseModel):
    
    message: str


class RegistrationResponse(BaseModel):
    message: str
    username: str
    email: str
    role: str

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


# Replace "your-email@outlook.com" and "YOUR_APP_PASSWORD" with your actual Outlook email and app password.




def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

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
    

@app.post("/register/", response_model=RegistrationResponse)
def register_user(
    username: str = Form(...),
    email: EmailStr = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    # Normalize the email and determine the role based on it
    email = email.lower()
    role = "doctor" if email.endswith("-d") else "patient"
    if email.endswith("-d"):
        email = email[:-2]

    # Check if the user already exists
    if db.query(User).filter(User.email == email).first():
        raise HTTPException(status_code=400, detail="Email already in use")

    # Create a new user and set is_active to True immediately
    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    new_user = User(username=username, email=email, password_hash=hashed_password, role=role, is_active=True)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # Construct and send a welcome email
    body = f"Hello {username},\n\nWelcome to our service! We are excited to have you on board."
    send_email("Welcome to Our Service", email, body)

    # Return a response indicating successful registration
    return RegistrationResponse(
        message="Registration successful, and a welcome email has been sent.",
        username=username,
        email=email,
        role=role,
    )



@app.post("/login/", response_model=LoginResponse)
def login_user(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if user and bcrypt.checkpw(form_data.password.encode(), user.password_hash.encode()):
        access_token = create_access_token(data={"sub": user.username}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
        return {"access_token": access_token, "token_type": "bearer"}
    else:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")





@app.get("/users/me/")
def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user


@app.post("/forgot-password/", response_model=PasswordResetResponse)
def forgot_password(request: PasswordResetRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == request.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    reset_token = create_access_token({"sub": user.username}, timedelta(minutes=15))
    
    # Use the specialized function to send the reset email
    send_password_reset_email(user.email, user.username, reset_token)

    return PasswordResetResponse(message="Password reset email sent successfully")



# Function to send reset email
def send_password_reset_email(email: str, username: str, token: str):
    try:
        reset_link = f"http://yourfrontenddomain.com/reset-password?token={token}"
        subject = "Password Reset Request"
        body = f"Hello {username},\n\nPlease follow this link to reset your password: {reset_link}\n\nIf you did not request this, please ignore this email."
        send_email(subject, email, body)
    except Exception as e:
        print(f"Failed to send password reset email: {e}")
        # Optionally, you might want to handle this more gracefully in a production environment
        raise HTTPException(status_code=500, detail="Failed to send password reset email.")

# Endpoint to reset password using token
@app.post("/reset-password/", response_model=PasswordResetResponse)
def reset_password(token: str, new_password: str, db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if not username:
            raise HTTPException(status_code=403, detail="Invalid token")
        
        # Find user by username and update password
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
    

