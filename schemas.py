from pydantic import BaseModel, EmailStr
from typing import List

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str

class UserOut(BaseModel):
    id: str
    username: str
    email: EmailStr
    role: str

class Token(BaseModel):
    access_token: str
    token_type: str

class RoleUpdate(BaseModel):
    role: str