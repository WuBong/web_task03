from flask import Flask
from model import db
from forms import register, login

app = Flask(__name__)

# 데이터베이스 설정
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'

# 데이터베이스 초기화
db.init_app(app)

# 라우트 등록
app.add_url_rule('/register', 'register', register, methods=['POST'])
app.add_url_rule('/login', 'login', login, methods=['POST'])

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # 데이터베이스 생성
    app.run(debug=True)
