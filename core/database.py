from sqlmodel import SQLModel, create_engine, Session
from core.config import settings

engine = create_engine(settings.database_url, connect_args={"check_same_thread": False})

def init_db():
    SQLModel.metadata.create_all(engine)

def get_session():
    return Session(engine)