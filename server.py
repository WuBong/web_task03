# server.py
from flask import Flask, render_template, request, jsonify, redirect, url_for, make_response
from model import db, User
from forms import register, login
import jwt
import datetime

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'

db.init_app(app)

# 로그인 페이지 렌더링
@app.route('/login', methods=['GET'])
def login_page():
    return render_template('login.html')

# 로그인 처리 API
@app.route('/login', methods=['POST'])
def login_user():
    return login()

# 회원가입 페이지 렌더링
@app.route('/signup', methods=['GET'])
def signup_page():
    return render_template('signup.html')

# 회원가입 처리 API
@app.route('/register', methods=['POST'])
def register_user():
    return register()


# 메인 페이지 (로그인 여부에 따라 다르게 렌더링)
@app.route('/', methods=['GET'])
def index():
    token = request.cookies.get('token')  # 쿠키에서 토큰을 가져옵니다
    user_authenticated = False

    if token:
        try:
            # JWT 토큰 유효성 검사
            decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            user_authenticated = True  # 인증된 사용자로 처리
        except jwt.ExpiredSignatureError:
            pass  # 토큰이 만료되었으면 인증되지 않은 상태로 처리
        except jwt.InvalidTokenError:
            pass  # 유효하지 않은 토큰일 경우 처리

    return render_template('index.html', is_authenticated=user_authenticated)


# 로그아웃 처리
# 로그아웃 처리
@app.route('/logout', methods=['GET'])
def logout():
    response = redirect(url_for('index'))
    response.delete_cookie('token')  # 쿠키에서 토큰 삭제
    return response


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
