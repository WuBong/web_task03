# server.py
from flask import Flask, render_template, request, jsonify, redirect, url_for, make_response
from model import db, User
from forms import register, login
import jwt
import datetime
from functools import wraps
from werkzeug.security import check_password_hash, generate_password_hash

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

# JWT 토큰 유효성 검사를 위한 미들웨어
def token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.cookies.get('token')  # 쿠키에서 토큰을 가져옵니다
        if not token:
            return jsonify({'message': 'Token is missing!'}), 403  # 토큰이 없으면 403 에러

        try:
            # 토큰 유효성 검사
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(id=data['id']).first()
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token!'}), 401
        
        # 인증된 사용자 정보를 함수로 전달
        return f(current_user, *args, **kwargs)

    return decorated_function

# 회원정보 수정 페이지 렌더링 (로그인한 사용자만 접근 가능)
@app.route('/update', methods=['GET'])
@token_required
def update_user_page(current_user):
    return render_template('update_user.html', user=current_user)

# 회원 정보 수정 (PUT)
@app.route('/user', methods=['PUT'])
@token_required
def update_user(current_user):
    try:
        data = request.get_json()

        if not data:
            return jsonify({'message': 'No data provided'}), 400

        # 비밀번호 변경
        if 'password' in data:
            new_password = data['password']
            if len(new_password) < 6:  # 비밀번호 최소 길이 체크
                return jsonify({'message': 'Password must be at least 6 characters'}), 400
            current_user.password = generate_password_hash(new_password)
        
        # 사용자 이름 수정
        if 'username' in data:
            current_user.username = data['username']
        
        # 데이터베이스에 변경 사항 저장
        db.session.commit()

        return jsonify({'message': 'User information updated successfully'}), 200
    except Exception as e:
        return jsonify({'message': f'Error: {str(e)}'}), 500
    
    


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
