from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase

# путь к SQLite базе
DATABASE_URL = "sqlite:///./auth.db"


# базовый класс для моделей
class Base(DeclarativeBase):
    pass


# engine - ядро подключения к БД
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
)

# фабрика сессий
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)


# Dependency для FastAPI
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
