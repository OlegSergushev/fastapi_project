from fastapi import FastAPI
from app.auth.router import router as auth_router
from app.database import engine
from app import models

app = FastAPI()

# Создаем таблицы
models.Base.metadata.create_all(bind=engine)

app.include_router(auth_router)


@app.get("/")
def root():
    return {"message": "Hello!"}



