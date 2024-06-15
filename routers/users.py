from fastapi import APIRouter, FastAPI, Form, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from pydantic import BaseModel
from typing import Optional, List
from enum import Enum
from jose import JWTError, jwt
from datetime import datetime, timedelta
from services.mailersend import send_email
import random
import string
from services.db import users_collection  # Import the users collection from the database module

# Constants for JWT
SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

router = APIRouter(prefix="/users", tags=["user, users"])

def generate_otp(length=6):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))

# User roles
class UserRole(str, Enum):
    admin = "admin"
    customer = "customer"
    worker = "worker"

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(email: str):
    return users_collection.find_one({"email": email})

def authenticate_user(email: str, password: str):
    user = get_user(email)
    if not user:
        return False
    if not verify_password(password, user["password"]):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = email
    except JWTError:
        raise credentials_exception
    user = get_user(email=token_data)
    if user is None:
        raise credentials_exception
    return user

# Pydantic model for user registration
class User(BaseModel):
    email: str
    password: str
    role: UserRole
    phone_number: Optional[str] = None
    reset_password_otp: Optional[str] = None  # Field to store reset password OTP

class Token(BaseModel):
    access_token: str
    token_type: str

@router.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["email"]}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@router.get("/users/me", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user

@router.post("/register", response_model=User)
async def register_user(user: User):
    user_dict = user.dict()
    user_dict['password'] = get_password_hash(user.password)
    users_collection.insert_one(user_dict)
    return user_dict

@router.get("/users", response_model=List[User])
async def get_users():
    users = list(users_collection.find({}, {"_id": 0, "password": 0}))
    return users

@router.post("/login", tags=["login"])
async def login(email: str = Form(...), password: str = Form(...)):
    # Check if user exists
    user = get_user(email)
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    # Verify password
    if not verify_password(password, user['password']):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    # Check user role
    if user['role'] == UserRole.admin:
        # Generate and send OTP
        otp = generate_otp(8)
        # Implement OTP generation and sending logic here
        send_email(user["email"], "User Login", f"User login successfully. Check your email for OTP: {otp}")
        return {"message": "OTP sent to email/phone", 'otp': otp}
    elif user['role'] == UserRole.customer:
        # Give options to log in with password or OTP
        otp = generate_otp(6)
        # Implement OTP generation and sending logic here
        send_email(user["email"], "User Login", f"User login successfully. Check your email for OTP: {otp}")
        return {"message": "Choose login method: Password or OTP", 'otp': otp}
    elif user['role'] == UserRole.worker:
        # Login with phone number and OTP
        otp = generate_otp(7)
        # Implement OTP generation and sending logic here
        send_email(user["email"], "User Login", f"User login successfully. Check your email for OTP: {otp}")
        return {"message": "OTP sent to phone", 'otp': otp}


