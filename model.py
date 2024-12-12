# model.py
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime


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

class Application(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    job_id = db.Column(db.Integer, db.ForeignKey('job.id'), nullable=False)
    status = db.Column(db.String(20), default='대기중')  # 상태: 대기중, 합격, 불합격 등
    applied_at = db.Column(db.DateTime, default=datetime.utcnow)  # 지원 일자
    user = db.relationship('User', backref=db.backref('applications', lazy=True))
    job = db.relationship('Job', backref=db.backref('applications', lazy=True))

    def __repr__(self):
        return f"<Application {self.id} - User: {self.user.username}, Job: {self.job.title}, Status: {self.status}>"

class Bookmark(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # 사용자 ID
    job_id = db.Column(db.Integer, db.ForeignKey('job.id'), nullable=False)   # 북마크한 채용공고 ID
    created_at = db.Column(db.DateTime, default=datetime.utcnow)              # 북마크 추가 시간