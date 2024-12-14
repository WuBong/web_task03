# server.py
from flask import Flask, render_template, request, jsonify, redirect, url_for, make_response
from model import db, User, Job, Application, Bookmark
import jwt
from sqlalchemy import or_
from datetime import datetime
import base64
import re
from functools import wraps
from werkzeug.security import check_password_hash, generate_password_hash
from flask import Flask, request, jsonify
import sqlite3



app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'


db.init_app(app)



# 기존 데이터베이스에 새로운 테이블 추가
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # 모든 모델(User, Application)을 한 데이터베이스에 생성
        print("All tables created successfully in users.db!")

# 로그인 페이지 렌더링
@app.route('/login', methods=['GET'])
def login_page():
    return render_template('login.html')

# 로그인 처리 API
@app.route('/login', methods=['POST'])
def login_user():
    import datetime
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

                # 로그인 성공 시 Access Token 생성 (유효 기간 1시간)
        access_token = jwt.encode(
            {'id': user.id, 'email': user.email, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)},
            app.config['SECRET_KEY'],
            algorithm='HS256'
        )

        # Refresh Token 생성 (유효 기간 30일)
        refresh_token = jwt.encode(
            {'id': user.id, 'email': user.email, 'exp': datetime.datetime.utcnow() + datetime.timedelta(days=30)},
            app.config['SECRET_KEY'],
            algorithm='HS256'
        )
        

        return jsonify({'message': 'Login successful', 'access_token': access_token, 'refresh_token': refresh_token}), 200
    except Exception as e:
        return jsonify({'message': f'Error: {str(e)}'}), 500

@app.route('/refresh', methods=['POST'])
def refresh_token():
    try:
        data = request.get_json()

        if not data or not data.get('refresh_token'):
            return jsonify({'message': 'Refresh token is required'}), 400

        # Refresh token 검증
        try:
            decoded_token = jwt.decode(data['refresh_token'], app.config['SECRET_KEY'], algorithms=["HS256"])
            user_id = decoded_token['id']
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Refresh token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid refresh token'}), 401

        # 새 Access Token 발급
        user = User.query.get(user_id)
        if not user:
            return jsonify({'message': 'User not found'}), 404

        # Access Token 생성 (1시간 유효)
        access_token = jwt.encode(
            {'id': user.id, 'email': user.email, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)},
            app.config['SECRET_KEY'],
            algorithm='HS256'
        )

        return jsonify({'access_token': access_token}), 200

    except Exception as e:
        return jsonify({'message': f'Error: {str(e)}'}), 500

# 회원가입 페이지 렌더링
@app.route('/signup', methods=['GET'])
def signup_page():
    return render_template('signup.html')

# 이메일 형식 검증 함수
def is_valid_email(email):
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(email_regex, email) is not None

# 회원가입 처리 API
@app.route('/register', methods=['POST'])
def register_user():
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
        print(data['password'])
        new_user = User(username=data['username'], email=data['email'], password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return jsonify({'message': 'User registered successfully'}), 201
    except Exception as e:
        return jsonify({'message': f'Error: {str(e)}'}), 500


@app.route('/', methods=['GET'])
def index():
    token = request.cookies.get('access_token')  # 쿠키에서 Access Token을 가져옵니다
    refresh_token = request.cookies.get('refresh_token')  # 쿠키에서 Refresh Token을 가져옵니다
    user_authenticated = False

    if token:
        try:
            # JWT 토큰 유효성 검사 (Access Token)
            decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            user_authenticated = True  # 인증된 사용자로 처리
        except jwt.ExpiredSignatureError:
            # Access Token이 만료되었으면 Refresh Token을 사용하여 새로운 Access Token을 요청
            if refresh_token:
                # Refresh Token이 있을 경우, 토큰 갱신 요청
                try:
                    decoded_refresh_token = jwt.decode(refresh_token, app.config['SECRET_KEY'], algorithms=["HS256"])
                    # 새 Access Token을 발급 받기 위해 refresh_token을 사용
                    user_authenticated = True  # 인증된 사용자로 처리
                except jwt.ExpiredSignatureError:
                    pass  # Refresh Token도 만료되었으면 인증되지 않은 상태로 처리
                except jwt.InvalidTokenError:
                    pass  # Refresh Token이 유효하지 않으면 인증되지 않은 상태로 처리
        except jwt.InvalidTokenError:
            pass  # 유효하지 않은 Access Token일 경우 인증되지 않은 상태로 처리

    return render_template('index.html', is_authenticated=user_authenticated)


# 로그아웃 처리
@app.route('/logout', methods=['GET'])
def logout():
    response = redirect(url_for('index'))
    response.delete_cookie('access_token')  # 쿠키에서 토큰 삭제 (Access Token)
    response.delete_cookie('refresh_token')  # 쿠키에서 Refresh Token 삭제
    return response

# JWT 토큰 유효성 검사를 위한 미들웨어
def token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.cookies.get('access_token')  # 쿠키에서 토큰을 가져옵니다
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
    
# 회원 탈퇴 (DELETE)
@app.route('/user', methods=['DELETE'])
@token_required
def delete_user(current_user):
    try:
        # 사용자 삭제 로직 (예: current_user 삭제)
        db.session.delete(current_user)
        db.session.commit()

        # 쿠키에서 토큰 삭제
        response = jsonify({'message': 'User account deleted successfully'})
        response.delete_cookie('access_token', path='/')
        response.delete_cookie('refresh_token', path='/')

        # 추가적으로 토큰이 HttpOnly와 Secure로 설정되었으면, 이를 명시해줘야 합니다.
        response.delete_cookie('access_token', path='/', secure=True, httponly=True)
        response.delete_cookie('refresh_token', path='/', secure=True, httponly=True)

        return response, 200
    except Exception as e:
        return jsonify({'message': f'Error: {str(e)}'}), 500
    

@app.route('/jobs', methods=['GET'])
@token_required
def job_list(current_user):
    # 기본값 설정
    page = request.args.get('page', 1, type=int)
    per_page = 20
    offset = (page - 1) * per_page
    sort_by = request.args.get('sort_by', 'today')
    search_keyword = request.args.get('search', '')
    location_filter = request.args.get('location', '')
    experience_filter = request.args.get('experience', '')
    
    # 기본 쿼리
    query = Job.query

    # 검색 조건 추가
    if search_keyword:
        query = query.filter(
            or_(
                Job.title.like(f'%{search_keyword}%'),
                Job.company.like(f'%{search_keyword}%'),
                Job.requirement.like(f'%{search_keyword}%')
            )
        )

    # 필터링 조건 추가
    if location_filter:
        query = query.filter(Job.location.like(f'%{location_filter}%'))
    if experience_filter:
        if experience_filter == "1~5":
            query = query.filter(Job.experience.like('%1년%') |
                                 Job.experience.like('%2년%') |
                                 Job.experience.like('%3년%') |
                                 Job.experience.like('%4년%') |
                                 Job.experience.like('%5년%'))
        elif experience_filter == "6~10":
            query = query.filter(Job.experience.like('%6년%') |
                                 Job.experience.like('%7년%') |
                                 Job.experience.like('%8년%') |
                                 Job.experience.like('%9년%') |
                                 Job.experience.like('%10년%'))
        elif experience_filter == "11~15":
            query = query.filter(Job.experience.like('%11년%') |
                                 Job.experience.like('%12년%') |
                                 Job.experience.like('%13년%') |
                                 Job.experience.like('%14년%') |
                                 Job.experience.like('%15년%'))
        elif experience_filter == "16~":
            query = query.filter(Job.experience.like('%16년%') |
                                 Job.experience.like('%17년%') |
                                 Job.experience.like('%18년%') |
                                 Job.experience.like('%19년%') |
                                 Job.experience.like('%20년%') |
                                 Job.experience.like('%21년%'))
        else:
            query = query.filter(Job.experience.like(f'%{experience_filter}%'))

    # 정렬 기준 추가
    if sort_by == 'company':
        query = query.order_by(Job.company)
    else:
        query = query.order_by(Job.today.desc())

    # 총 공고 수 계산
    total_jobs = query.count()

    # 페이지네이션 적용
    jobs = query.offset(offset).limit(per_page).all()

    # 총 페이지 수 계산
    total_pages = (total_jobs // per_page) + (1 if total_jobs % per_page > 0 else 0)


    # 현재 사용자가 북마크한 job_id 목록 조회
    bookmarked_job_ids = {b.job_id for b in Bookmark.query.filter_by(user_id=current_user.id).all()}

    # jobs에 북마크 상태 추가
    jobs = query.offset(offset).limit(per_page).all()
    for job in jobs:
        job.is_bookmarked = job.id in bookmarked_job_ids

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
    # Job ID에 해당하는 공고 조회
    job = Job.query.get(job_id)  # job_id에 해당하는 Job 객체를 조회

    if not job:
        return render_template('error.html', message="해당 공고를 찾을 수 없습니다."), 404

    # 조회수 증가
    job.views += 1
    db.session.commit()  # 변경 사항을 커밋
    # 관련 공고 추천 (location 및 experience 기준)
    related_jobs = Job.query.filter(
        Job.location == job.location,
        Job.id != job_id
    ).limit(5).all()  # 최대 5개의 관련 공고만 조회

    print(related_jobs)

    return render_template('job_detail.html', job=job, related_jobs=related_jobs)

@app.route('/applications', methods=['POST'])
@token_required  # 인증 확인 데코레이터
def apply_for_job(current_user):
    job_id = request.json.get('job_id')
    
    # Job 존재 여부 확인
    job = Job.query.get(job_id)
    if not job:
        return jsonify({"message": "해당 공고를 찾을 수 없습니다."}), 404
    
    # 중복 지원 체크
    existing_application = Application.query.filter_by(user_id=current_user.id, job_id=job_id).first()
    if existing_application:
        return jsonify({"message": "이미 지원한 공고입니다."}), 400
    
    # 지원 정보 저장
    new_application = Application(
        user_id=current_user.id,
        job_id=job_id,
        status='대기중',
        applied_at=datetime.utcnow()
    )
    db.session.add(new_application)
    db.session.commit()

    return jsonify({"message": "지원이 완료되었습니다."}), 201

@app.route('/applications', methods=['GET'])
@token_required
def view_applications(current_user):
    # 사용자 ID를 기반으로 지원 목록 가져오기
    applications = db.session.query(
        Application,
        Job.title,
        Job.company
    ).join(Job, Application.job_id == Job.id).filter(Application.user_id == current_user.id).all()
    
    # 데이터를 HTML로 전달
    applications_list = [
        {
            "job_id": app.Application.job_id,
            "company": app.company,
            "title": app.title,
            "status": app.Application.status,
            "applied_at": app.Application.applied_at.strftime("%Y-%m-%d %H:%M:%S")
        } for app in applications
    ]
    return render_template(
        'applications.html',
        user_name=current_user.username,
        applications=applications_list
    )

@app.route('/applications/<int:job_id>', methods=['DELETE'])
@token_required  # 인증 확인 데코레이터
def cancel_application(current_user, job_id):
    # 사용자 ID와 job_id에 해당하는 지원 내역 찾기
    application = db.session.query(Application).join(Job, Application.job_id == job_id) \
        .filter(Application.user_id == current_user.id, Application.job_id == job_id).first()

    if not application:
        return jsonify({"message": "해당 공고에 대한 지원 내역을 찾을 수 없습니다."}), 404

    # 콘솔로 Application 정보 출력
    print(f"Application ID: {application.id}")
    print(f"User ID: {application.user_id}")
    print(f"Job ID: {application.job_id}")
    print(f"Status: {application.status}")
    print(f"Applied At: {application.applied_at.strftime('%Y-%m-%d %H:%M:%S')}")

    # 지원 상태가 '대기중'일 때만 취소 가능
    if application.status != '대기중':
        return jsonify({"message": "대기중인 지원만 취소할 수 있습니다."}), 400

    try:
        # 조건에 맞는 지원 내역 삭제
        db.session.delete(application)
        db.session.commit()
    except Exception as e:
        # 오류 발생 시 롤백
        print(e)
        db.session.rollback()
        return jsonify({"message": "지원 취소 중 오류가 발생했습니다.", "error": str(e)}), 500

    return jsonify({"message": "지원이 취소되었습니다."}), 200


@app.route('/bookmarks', methods=['POST'])
@token_required  # 인증 데코레이터
def toggle_bookmark(current_user):
    data = request.get_json()
    job_id = data.get('job_id')

    # job_id 유효성 확인
    job = Job.query.get(job_id)
    if not job:
        return jsonify({"success": False, "message": "해당 공고를 찾을 수 없습니다."}), 404

    # 북마크 여부 확인
    bookmark = Bookmark.query.filter_by(user_id=current_user.id, job_id=job_id).first()
    
    if bookmark:
        # 북마크 제거
        db.session.delete(bookmark)
        db.session.commit()
        return jsonify({"success": True, "message": "북마크가 제거되었습니다."}), 200
    else:
        # 북마크 추가
        new_bookmark = Bookmark(user_id=current_user.id, job_id=job_id)
        db.session.add(new_bookmark)
        db.session.commit()
        return jsonify({"success": True, "message": "북마크가 추가되었습니다."}), 201
    
@app.route('/toggle_bookmark/<int:job_id>', methods=['POST'])
@token_required
def toggle_bookmarks(current_user, job_id):
    # job_id 유효성 확인
    job = Job.query.get(job_id)
    if not job:
        return jsonify({"success": False, "message": "해당 공고를 찾을 수 없습니다."}), 404

    # 북마크 여부 확인
    bookmark = Bookmark.query.filter_by(user_id=current_user.id, job_id=job_id).first()
    
    if bookmark:
        # 북마크 제거
        db.session.delete(bookmark)
        db.session.commit()
        return jsonify({"success": True, "message": "북마크가 제거되었습니다."}), 200
    else:
        # 북마크 추가
        new_bookmark = Bookmark(user_id=current_user.id, job_id=job_id)
        db.session.add(new_bookmark)
        db.session.commit()
        return jsonify({"success": True, "message": "북마크가 추가되었습니다."}), 201

@app.route('/bookmarks')
@token_required  # 인증 데코레이터
def bookmarked_jobs(current_user):
    # 기본값 설정
    page = request.args.get('page', 1, type=int)
    per_page = 20
    offset = (page - 1) * per_page

    # 북마크된 공고 조회 (최신순 정렬)
    query = db.session.query(
        Job.id,
        Job.title,
        Job.company,
        Job.location,
        Job.experience,
        Job.deadline,
        Bookmark.id.label('bookmark_id')  # 북마크된 여부 확인용
    ).join(Bookmark, Bookmark.job_id == Job.id).filter(
        Bookmark.user_id == current_user.id
    ).order_by(Bookmark.created_at.desc())

    print(query)

    # 총 북마크 수 계산
    total_bookmarks = query.count()

    # 페이지네이션 적용
    bookmarked_jobs = query.offset(offset).limit(per_page).all()

    # 총 페이지 수 계산
    total_pages = (total_bookmarks // per_page) + (1 if total_bookmarks % per_page > 0 else 0)

    # HTML 템플릿 렌더링
    return render_template(
        'bookmarks.html',
        jobs=bookmarked_jobs,
        page=page,
        per_page=per_page,
        total_pages=total_pages,
        total_jobs=total_bookmarks
    )





if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port= 3000, host = '0.0.0.0')
