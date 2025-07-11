from fastapi import APIRouter, Depends, HTTPException
from typing import List
from sqlalchemy.orm import Session
from models import User
from schemas import UserOut, RoleUpdate
from auth.utils import decode_token, get_user_by_id
from database import get_db
from fastapi.security import OAuth2PasswordBearer

router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

@router.get("/", response_model=List[UserOut])
def list_users(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    user = decode_token(token, db)
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admins only")
    return db.query(User).all()

@router.put("/{user_id}/role", response_model=UserOut)
def update_user_role(user_id: str, data: RoleUpdate, token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    admin = decode_token(token, db)
    if admin.role != "admin":
        raise HTTPException(status_code=403, detail="Admins only")
    user = get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.role = data.role
    db.commit()
    db.refresh(user)
    return user

@router.delete("/{user_id}")
def delete_user(user_id: str, token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    admin = decode_token(token, db)
    if admin.role != "admin":
        raise HTTPException(status_code=403, detail="Admins only")
    user = get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    db.delete(user)
    db.commit()
    return {"message": "User deleted successfully"}
