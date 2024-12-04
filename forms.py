# forms.py
import re
from flask import request, jsonify, current_app as app
from werkzeug.security import generate_password_hash, check_password_hash
from model import db, User
import jwt
import datetime

# 이메일 형식 검증 함수
def is_valid_email(email):
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(email_regex, email) is not None

# 회원가입
def register():
    try:
        data = request.get_json()

        if not data or not data.get('username') or not data.get('email') or not data.get('password'):
            return jsonify({'message': 'Invalid input'}), 400

        # 이메일 형식 검증
        if not is_valid_email(data['email']):
            return jsonify({'message': 'Invalid email format'}), 400

        if User.query.filter_by(email=data['email']).first():
            return jsonify({'message': 'Email already registered'}), 409

        # 비밀번호 해싱 후 저장
        hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
        new_user = User(username=data['username'], email=data['email'], password=hashed_password)

        db.session.add(new_user)
        db.session.commit()

        return jsonify({'message': 'User registered successfully'}), 201
    except Exception as e:
        return jsonify({'message': f'Error: {str(e)}'}), 500

# 로그인
def login():
    try:
        data = request.get_json()

        # 요청 데이터가 없거나 필요한 정보가 없을 경우
        if not data or not data.get('email') or not data.get('password'):
            return jsonify({'message': 'Invalid input'}), 400

        # 이메일로 사용자 확인
        user = User.query.filter_by(email=data['email']).first()

        # 사용자가 없거나 비밀번호가 맞지 않으면
        if not user or not user.check_password(data['password']):
            return jsonify({'message': 'Invalid email or password'}), 401

        # 로그인 성공 시 JWT 토큰 생성
        token = jwt.encode(
            {'id': user.id, 'email': user.email, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)},
            app.config['SECRET_KEY'],
            algorithm='HS256'
        )

        return jsonify({'message': 'Login successful', 'token': token}), 200
    except Exception as e:
        return jsonify({'message': f'Error: {str(e)}'}), 500
