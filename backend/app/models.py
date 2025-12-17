from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey, Enum as SQLEnum
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime
import enum

Base = declarative_base()
engine = create_engine('sqlite:///scanforge.db', echo=True)  # Echo for debug
SessionLocal = sessionmaker( bind=engine )

class Severity(enum.Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"

class Category(enum.Enum):
    SECRETS = "1"
    INSECURE = "2"
    MISCONFIG = "3"
    DEPS = "4"

class Repo(Base):
    __tablename__ = "repos"
    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True, index=True)
    url = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    scans = relationship("Scan", back_populates="repo")

class Scan(Base):
    __tablename__ = "scans"
    id = Column(Integer, primary_key=True)
    repo_id = Column(Integer, ForeignKey("repos.id"))
    timestamp = Column(DateTime, default=datetime.utcnow)
    repo = relationship("Repo", back_populates="scans")
    issues = relationship("Issue", back_populates="scan")

class Issue(Base):
    __tablename__ = "issues"
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    rule_id = Column(String, index=True)  # e.g., '1.1'
    severity = Column(SQLEnum(Severity))
    category = Column(SQLEnum(Category))
    description = Column(String)
    file_path = Column(String)
    line_number = Column(Integer)
    snippet = Column(String)
    status = Column(String, default="Open")  # Open/Fixed/Ignored
    ai_suggestion = Column(String, nullable=True)
    scan = relationship("Scan", back_populates="issues")

# Create tables
Base.metadata.create_all(engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()