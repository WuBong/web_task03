# server.py
from flask import Flask, render_template, request, jsonify, redirect, url_for, make_response
from model import db, User
from forms import register, login
import jwt

from functools import wraps
from werkzeug.security import check_password_hash, generate_password_hash
import sqlite3

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
    

def get_db_connection():
    conn = sqlite3.connect('webcrawling/saramin_jobs.db')
    conn.row_factory = sqlite3.Row  # 딕셔너리 형식으로 데이터를 반환하도록 설정
    return conn

@app.route('/jobs')
def job_list():
    # SQLite 데이터베이스 연결
    conn = sqlite3.connect('webcrawling/saramin_jobs.db')
    cursor = conn.cursor()

    # 기본값 설정
    page = request.args.get('page', 1, type=int)
    per_page = 20
    offset = (page - 1) * per_page
    sort_by = request.args.get('sort_by', 'today')
    search_keyword = request.args.get('search', '')
    location_filter = request.args.get('location', '')
    experience_filter = request.args.get('experience', '')

    # 기본 쿼리
    query = "SELECT * FROM jobs WHERE 1=1"

    # 검색 조건 추가
    if search_keyword:
        query += f" AND (title LIKE '%{search_keyword}%' OR company LIKE '%{search_keyword}%' OR requirement LIKE '%{search_keyword}%')"

    # 필터링 조건 추가
    if location_filter:
        query += f" AND location LIKE '%{location_filter}%'"
    if experience_filter:
        if experience_filter == "1~5":
            query += " AND (experience LIKE '%1년%' OR experience LIKE '%2년%' OR experience LIKE '%3년%' OR experience LIKE '%4년%' OR experience LIKE '%5년%')"
        elif experience_filter == "6~10":
            query += " AND (experience LIKE '%6년%' OR experience LIKE '%7년%' OR experience LIKE '%8년%' OR experience LIKE '%9년%' OR experience LIKE '%10년%')"
        elif experience_filter == "11~15":
            query += " AND (experience LIKE '%11년%' OR experience LIKE '%12년%' OR experience LIKE '%13년%' OR experience LIKE '%14년%' OR experience LIKE '%15년%')"
        elif experience_filter == "16~":
            query += " AND (experience LIKE '%16년%' OR experience LIKE '%17년%' OR experience LIKE '%18년%' OR experience LIKE '%19년%' OR experience LIKE '%20년%' OR experience LIKE '%21년%')"
        else:
            query += f" AND experience LIKE '%{experience_filter}%'"

    # 정렬 기준 추가
    if sort_by == 'company':
        query += " ORDER BY company"
    else:
        query += " ORDER BY today DESC"

    # 총 공고 수 계산
    cursor.execute(query)
    total_jobs = len(cursor.fetchall())

    # 페이지네이션 적용
    query += f" LIMIT {per_page} OFFSET {offset}"
    cursor.execute(query)
    jobs = cursor.fetchall()

    # 총 페이지 수 계산
    total_pages = (total_jobs // per_page) + (1 if total_jobs % per_page > 0 else 0)

    conn.close()

    # HTML 템플릿 렌더링
    return render_template(
        'job_list.html',
        jobs=jobs,
        page=page,
        per_page=per_page,
        total_pages=total_pages,
        total_jobs=total_jobs,
        search_keyword=search_keyword,
        location_filter=location_filter,
        experience_filter=experience_filter,
    )

#채용공고 상세페이지
@app.route('/jobs/<int:job_id>', methods=['GET'])
def get_job_detail(job_id):
    conn = sqlite3.connect('webcrawling/saramin_jobs.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # 조회수 증가
    cursor.execute('UPDATE jobs SET views = views + 1 WHERE id = ?', (job_id,))
    conn.commit()

    # 현재 공고 정보 조회
    cursor.execute('SELECT * FROM jobs WHERE id = ?', (job_id,))
    job = cursor.fetchone()

    if not job:
        conn.close()
        return render_template('error.html', message="해당 공고를 찾을 수 없습니다."), 404

    # 관련 공고 추천 (location 및 experience 기준)
    cursor.execute(
        '''
        SELECT id, title, company, location, experience 
        FROM jobs 
        WHERE location = ? AND experience = ? AND id != ?
        LIMIT 5
        ''',
        (job['location'], job['experience'], job_id)
    )
    related_jobs = cursor.fetchall()
    conn.close()

    return render_template('job_detail.html', job=job, related_jobs=related_jobs)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
