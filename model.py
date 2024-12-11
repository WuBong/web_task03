# model.py
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    # 비밀번호 검증 메서드 추가
    def check_password(self, password):
        return check_password_hash(self.password, password)
    
class Job(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    today = db.Column(db.String(100))
    title = db.Column(db.String(100), unique=True, nullable=False)
    company = db.Column(db.String(100))
    url = db.Column(db.String(200))
    deadline = db.Column(db.String(100))
    location = db.Column(db.String(100))
    experience = db.Column(db.String(100))
    requirement = db.Column(db.String(500))
    jobtype = db.Column(db.String(100))
    jobday = db.Column(db.String(100))
    views = db.Column(db.Integer, default=0)


