from fastapi import FastAPI
from auth.routes import router as auth_router
from users.routes import router as users_router
from database import engine
from models import Base

app = FastAPI()
Base.metadata.create_all(bind=engine)

app.include_router(auth_router, prefix="/auth", tags=["Auth"])
app.include_router(users_router, prefix="/users", tags=["Users"])