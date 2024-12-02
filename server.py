from flask import Flask, render_template, request, jsonify
from model import db
from forms import register, login

app = Flask(__name__)

# 데이터베이스 설정
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'

# 데이터베이스 초기화
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
def signup():
    return render_template('signup.html')

# 회원가입 API
@app.route('/register', methods=['POST'])
def register_user():
    return register()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # 데이터베이스 생성
    app.run(debug=True)
