from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from uuid import uuid4
from sqlalchemy.orm import Session
from schemas import UserCreate, UserOut, Token
from models import User
from database import get_db
from auth.utils import hash_password, verify_password, create_access_token, get_user_by_email, decode_token

router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

@router.post("/register", response_model=UserOut)
def register(user: UserCreate, db: Session = Depends(get_db)):
    if get_user_by_email(db, user.email):
        raise HTTPException(status_code=409, detail="Email already registered")
    if len(user.password) < 8 or not any(char in '!@#$%^&*()' for char in user.password):
        raise HTTPException(status_code=400, detail="Weak password (min 8 chars & special char)")

    hashed_pw = hash_password(user.password)
    new_user = User(id=str(uuid4()), username=user.username, email=user.email, password_hash=hashed_pw)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

@router.post("/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = get_user_by_email(db, form_data.username)
    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token_data = {"sub": user.id, "email": user.email, "role": user.role}
    token = create_access_token(token_data)
    return {"access_token": token, "token_type": "bearer"}

@router.get("/me", response_model=UserOut)
def get_me(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    return decode_token(token, db)
