from flask import Flask, render_template
from flask_restx import Api, Resource, fields

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

# Swagger API 설정
api = Api(
    app,
    version='1.0',
    title='API 문서',
    description='Swagger 문서를 활용한 API',
    doc="/api-docs"  # Swagger UI 경로 설정
)

# 네임스페이스 정의
auth_api = api.namespace('auth', description='인증 관련 API')
user_api = api.namespace('user', description='회원 관련 API')
dashboard_api = api.namespace('dashboard', description='게시판 관련 API')
application_api = api.namespace('application', description='지원하기 및 북마크 API')

# 로그인 요청 모델 정의
login_request = api.model('LoginRequest', {
    'email': fields.String(required=True, description='사용자의 이메일', example='user@example.com'),
    'password': fields.String(required=True, description='사용자의 비밀번호', example='password123')
})

# 로그인 응답 모델 정의
login_response = api.model('LoginResponse', {
    'message': fields.String(description='응답 메시지', example='Login successful'),
    'access_token': fields.String(description='Access Token', example='access_token_string'),
    'refresh_token': fields.String(description='Refresh Token', example='refresh_token_string')
})

# 리프레시 토큰 요청 모델 정의
refresh_token_request = api.model('RefreshTokenRequest', {
    'refresh_token': fields.String(required=True, description='유효한 리프레시 토큰', example='your_refresh_token_here')
})

# 리프레시 토큰 응답 모델 정의
refresh_token_response = api.model('RefreshTokenResponse', {
    'access_token': fields.String(description='새로운 Access Token', example='new_access_token_string')
})

# 이메일 형식 검증 함수
def is_valid_email(email):
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(email_regex, email) is not None

# 회원가입 요청 모델 정의
register_request = api.model('RegisterRequest', {
    'username': fields.String(required=True, description='사용자 이름', example='johndoe'),
    'email': fields.String(required=True, description='사용자의 이메일', example='johndoe@example.com'),
    'password': fields.String(required=True, description='사용자의 비밀번호', example='password123')
})

# 회원가입 응답 모델 정의
register_response = api.model('RegisterResponse', {
    'message': fields.String(description='응답 메시지', example='User registered successfully')
})

# 인증된 사용자 상태 응답 모델 정의
auth_status = api.model('AuthStatus', {
    'is_authenticated': fields.Boolean(description='사용자 인증 여부', example=True)
})

# 로그아웃 API 모델 정의
logout_response = api.model('LogoutResponse', {
    'message': fields.String(description='로그아웃 메시지', example='Successfully logged out')
})

# 회원 정보 수정 모델 정의
update_user_request = api.model('UpdateUserRequest', {
    'username': fields.String(description='사용자 이름', example='new_username'),
    'password': fields.String(description='새로운 비밀번호', example='newpassword123')
})

# 응답 모델 정의
update_user_response = api.model('UpdateUserResponse', {
    'message': fields.String(description='응답 메시지', example='User information updated successfully')
})

# 응답 모델 정의
message_response = user_api.model('MessageResponse', {
    'message': fields.String(description='응답 메시지', example='User account deleted successfully')
})

# Swagger 모델 정의
job_model = api.model('Job', {
    'id': fields.Integer(description='Job ID', example=1),
    'title': fields.String(description='Job title', example='Software Engineer'),
    'company': fields.String(description='Company name', example='Company XYZ'),
    'location': fields.String(description='Job location', example='Seoul'),
    'experience': fields.String(description='Required experience', example='3년 이상'),
    'requirement': fields.String(description='Job requirements', example='Python, Flask, SQL'),
    'today': fields.String(description='Post date', example='2024-12-14'),
    'is_bookmarked': fields.Boolean(description='Is this job bookmarked by the user?', example=False)
})

# 구인구직공고에 대한 Swagger 문서 정의
job_query_params = api.parser()
job_query_params.add_argument('page', type=int, default=1, help='Page number', location='args')
job_query_params.add_argument('sort_by', type=str, choices=['today', 'company'], default='today', help='Sort by field', location='args')
job_query_params.add_argument('search', type=str, default='', help='Search keyword', location='args')
job_query_params.add_argument('location', type=str, default='', help='Location filter', location='args')
job_query_params.add_argument('experience', type=str, choices=['1~5', '6~10', '11~15', '16~'], default='', help='Experience filter', location='args')

# Swagger 모델 정의 (Job 상세 정보 응답)
job_detail_model = api.model('JobDetail', {
    'id': fields.Integer(description='Job ID', example=1),
    'title': fields.String(description='Job title', example='Software Engineer'),
    'company': fields.String(description='Company name', example='Company XYZ'),
    'location': fields.String(description='Job location', example='Seoul'),
    'experience': fields.String(description='Required experience', example='3년 이상'),
    'requirement': fields.String(description='Job requirements', example='Python, Flask, SQL'),
    'today': fields.String(description='Post date', example='2024-12-14'),
    'views': fields.Integer(description='Number of views', example=100),
})

# 관련 공고 모델 정의 (Job 목록)
related_job_model = api.model('RelatedJob', {
    'id': fields.Integer(description='Related Job ID', example=2),
    'title': fields.String(description='Job title', example='Backend Developer'),
    'company': fields.String(description='Company name', example='Company ABC'),
    'location': fields.String(description='Job location', example='Seoul'),
    'experience': fields.String(description='Required experience', example='2~5년'),
})

application_model = api.model('ApplicationResponse', {
    'job_id': fields.Integer(description='채용 공고 ID', example=1),
    'company': fields.String(description='회사명', example='회사 이름'),
    'title': fields.String(description='공고 제목', example='직무명'),
    'status': fields.String(description='지원 상태', example='대기중'),
    'applied_at': fields.String(description='지원 날짜', example='2024-12-14 13:45:00')
})


message_model = api.model('MessageResponse', {
    'message': fields.String(description='응답 메시지', example='지원이 완료되었습니다.')
})

class Application(db.Model):
    __tablename__ = 'applications'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    job_id = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(20), default='대기중', nullable=False)
    applied_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

class Job(db.Model):
    __tablename__ = 'jobs'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)

class Bookmark(db.Model):
    __tablename__ = 'bookmarks'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    job_id = db.Column(db.Integer, nullable=False)

# API 엔드포인트 설명용 Swagger 모델
application_model = api.model('Application', {
    'id': fields.Integer,
    'user_id': fields.Integer,
    'job_id': fields.Integer,
    'status': fields.String,
    'applied_at': fields.DateTime
})
# API 엔드포인트 설명용 Swagger 모델
bookmark_model = api.model('Bookmark', {
    'job_id': fields.Integer(required=True, description='채용 공고 ID'),
})

# 엔드포인트 정의
@auth_api.route('/login')
class LoginPage(Resource):
    @auth_api.doc(description="로그인 페이지를 렌더링하는 API")
    def get(self):
        """
        로그인 페이지를 렌더링하는 GET API
        """
        return render_template('login.html')

# 로그인 처리 API 엔드포인트
@auth_api.route('/login')
class LoginUser(Resource):
    @auth_api.doc(description="사용자의 로그인 처리 API")
    @auth_api.expect(login_request, validate=True)  # 요청 데이터의 형식을 Swagger에서 정의된 모델로 지정
    @auth_api.marshal_with(login_response)  # 응답 형식 정의
    def post(self):
        """
        사용자의 이메일과 비밀번호를 통해 로그인 처리 후 토큰 반환
        """
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

            return {'message': 'Login successful', 'access_token': access_token, 'refresh_token': refresh_token}, 200
        except Exception as e:
            return {'message': f'Error: {str(e)}'}, 500

# 리프레시 토큰 처리 API 엔드포인트
@auth_api.route('/refresh')
class RefreshToken(Resource):
    @auth_api.doc(description="리프레시 토큰을 사용하여 새로운 액세스 토큰을 발급받는 API")
    @auth_api.expect(refresh_token_request, validate=True)  # 요청 데이터의 형식을 Swagger에서 정의된 모델로 지정
    @auth_api.marshal_with(refresh_token_response)  # 응답 형식 정의
    def post(self):
        """
        리프레시 토큰을 검증하고, 유효하면 새로운 액세스 토큰을 반환
        """
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

            return {'access_token': access_token}, 200

        except Exception as e:
            return {'message': f'Error: {str(e)}'}, 500

# 회원가입 처리 API 엔드포인트
@auth_api.route('/register')
class RegisterUser(Resource):
    @auth_api.doc(description="새로운 사용자를 등록하는 API")
    @auth_api.expect(register_request, validate=True)  # 요청 데이터의 형식을 Swagger에서 정의된 모델로 지정
    @auth_api.marshal_with(register_response)  # 응답 형식 정의
    def post(self):
        """
        사용자의 이메일과 비밀번호를 통해 회원가입 처리
        """
        try:
            data = request.get_json()

            # 필수 데이터가 없으면 오류 반환
            if not data or not data.get('username') or not data.get('email') or not data.get('password'):
                return jsonify({'message': 'Invalid input'}), 400

            # 이메일 형식 검증
            if not is_valid_email(data['email']):
                return jsonify({'message': 'Invalid email format'}), 400

            # 이메일 중복 체크
            if User.query.filter_by(email=data['email']).first():
                return jsonify({'message': 'Email already registered'}), 409

            # 비밀번호 해싱 후 저장
            hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
            new_user = User(username=data['username'], email=data['email'], password=hashed_password)
            db.session.add(new_user)
            db.session.commit()

            return {'message': 'User registered successfully'}, 201

        except Exception as e:
            return {'message': f'Error: {str(e)}'}, 500

# 인증 처리 엔드포인트
@auth_api.route('/')
class AuthenticationStatus(Resource):
    @auth_api.doc(description="사용자의 인증 상태를 확인하는 API")
    @auth_api.marshal_with(auth_status)  # 응답 형식 정의
    def get(self):
        """
        Access Token과 Refresh Token을 확인하여 사용자의 인증 상태를 반환합니다.
        """
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
                    try:
                        decoded_refresh_token = jwt.decode(refresh_token, app.config['SECRET_KEY'], algorithms=["HS256"])
                        user_authenticated = True  # 인증된 사용자로 처리
                    except jwt.ExpiredSignatureError:
                        pass  # Refresh Token도 만료되었으면 인증되지 않은 상태로 처리
                    except jwt.InvalidTokenError:
                        pass  # Refresh Token이 유효하지 않으면 인증되지 않은 상태로 처리
            except jwt.InvalidTokenError:
                pass  # 유효하지 않은 Access Token일 경우 인증되지 않은 상태로 처리

        return {'is_authenticated': user_authenticated}, 200

# 로그아웃 처리 엔드포인트
@auth_api.route('/logout')
class Logout(Resource):
    @auth_api.doc(description="로그아웃 처리 API")
    @auth_api.marshal_with(logout_response)  # 응답 형식 정의
    def get(self):
        """
        사용자가 로그아웃을 하면, 쿠키에서 Access Token과 Refresh Token을 삭제하고,
        로그아웃 메시지를 반환합니다.
        """
        response = redirect(url_for('index'))
        response.delete_cookie('access_token')  # 쿠키에서 토큰 삭제 (Access Token)
        response.delete_cookie('refresh_token')  # 쿠키에서 Refresh Token 삭제
        return {'message': 'Successfully logged out'}, 200

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

# 회원 정보 수정 엔드포인트
@user_api.route('/')
class UpdateUser(Resource):
    @user_api.doc(description="회원 정보 수정 API")
    @user_api.expect(update_user_request)  # 요청 데이터 형식 정의
    @user_api.marshal_with(update_user_response)  # 응답 형식 정의
    
    def put(self):
        """
        사용자가 자신의 정보를 수정하는 API입니다.
        비밀번호를 변경하거나 사용자 이름을 수정할 수 있습니다.
        """
        data = request.get_json()

        if not data:
            return jsonify({'message': 'No data provided'}), 400

        # 비밀번호 변경
        if 'password' in data:
            new_password = data['password']
            if len(new_password) < 6:  # 비밀번호 최소 길이 체크
                return jsonify({'message': 'Password must be at least 6 characters'}), 400
            UpdateUser.password = generate_password_hash(new_password)
        
        # 사용자 이름 수정
        if 'username' in data:
            UpdateUser.username = data['username']
        
        # 데이터베이스에 변경 사항 저장
        db.session.commit()

        return {'message': 'User information updated successfully'}, 200

# 사용자 탈퇴 API
@user_api.route('/user')
class UserDelete(Resource):
    @user_api.doc(
        description="사용자 계정을 삭제합니다.",
        responses={
            200: ('성공', message_response),
            400: '잘못된 요청',
            401: '토큰이 유효하지 않거나 만료됨',
            404: '사용자를 찾을 수 없음',
            500: '서버 오류'
        }
    )
    @user_api.response(200, '사용자 계정이 성공적으로 삭제되었습니다.', message_response)
    @user_api.response(404, '사용자를 찾을 수 없습니다.')
    @user_api.response(401, '토큰이 유효하지 않거나 만료되었습니다.')
    def delete(self):
        """
        사용자의 계정을 삭제하는 API
        """
        # 실제 삭제 로직은 이곳에 추가됨
        return {'message': 'User account deleted successfully'}, 200

# 구인구직공고 api 정의
@dashboard_api.route('/jobs')
class JobList(Resource):
    @api.doc(
        description='구인구직공고가 올라오며 필터링기능 정렬기능도 포함함 페이지 기능도 있음',
        responses={
            200: 'Success',
            400: 'Invalid request',
            500: 'Internal server error'
        }
    )
    @api.expect(job_query_params)  # 쿼리 파라미터 문서화
    @api.marshal_list_with(job_model)  # 응답 형식 문서화
    def get(self):
        """
        필터링, 정렬 및 페이지화가 포함된 작업 목록 검색
        """
        args = job_query_params.parse_args()

        # 쿼리 파라미터 값 가져오기
        page = args.get('page', 1)
        per_page = 20
        offset = (page - 1) * per_page
        sort_by = args.get('sort_by', 'today')
        search_keyword = args.get('search', '')
        location_filter = args.get('location', '')
        experience_filter = args.get('experience', '')

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
            query = query.filter(Job.experience.like(f'%{experience_filter}%'))

        # 정렬 기준 추가
        if sort_by == 'company':
            query = query.order_by(Job.company)
        else:
            query = query.order_by(Job.today.desc())

        # 페이지네이션 적용
        jobs = query.offset(offset).limit(per_page).all()

        

        return jobs  # Swagger에서 정의한 응답 형식에 맞게 자동으로 응답

# 구인구직공고 세부공고 정의
@dashboard_api.route('/jobs/<int:job_id>')
class JobDetail(Resource):
    @api.doc(
        description='위치와 경험에 따른 관련 직무를 포함한 특정 채용 공고의 세부 정보를 확인하세요',
        responses={
            200: 'Success',
            404: 'Job not found',
            500: 'Internal server error'
        }
    )
    @api.marshal_with(job_detail_model)  # Job 상세 정보를 응답 형식으로 문서화
    @api.marshal_list_with(related_job_model)  # 관련 공고 목록 응답 형식으로 문서화
    def get(self, job_id):
        """
        관련 작업을 포함하여 job_id별 특정 채용 공고의 세부 정보를 가져옵니다.
        """
        job = Job.query.get(job_id)

        if not job:
            api.abort(404, 'Job not found')  # Job이 없으면 404 응답

        # 관련 공고 추천 (location 및 experience 기준)
        related_jobs = Job.query.filter(
            Job.location == job.location,
            Job.id != job_id
        ).limit(5).all()  # 최대 5개의 관련 공고만 조회

        # 조회수 증가
        job.views += 1
        db.session.commit()

        return {'job': job, 'related_jobs': related_jobs}  # 응답으로 job과 related_jobs 반환

#지원하기 api
@application_api.route('/applications')
class ApplyForJob(Resource):
    @api.doc(
        description='사용자가 특정 채용 공고에 지원하는 API',
        responses={
            201: '지원이 완료되었습니다.',
            400: '이미 지원한 공고입니다.',
            404: '공고를 찾을 수 없습니다.',
            500: '서버 오류'
        }
    )
    @api.expect(application_model)  # 요청 본문 형식
    @api.marshal_with(message_model)  # 응답 형식
    def post(self):
        """
        사용자가 특정 채용 공고에 지원하는 API입니다.
        - 채용 공고가 존재하는지 확인
        - 이미 지원한 공고인지 확인
        - 지원 정보를 데이터베이스에 저장
        """
        job_id = request.json.get('job_id')
        
        # Job 존재 여부 확인
        job = Job.query.get(job_id)
        if not job:
            api.abort(404, '해당 공고를 찾을 수 없습니다.')  # Job이 없으면 404 응답
        
        # 중복 지원 체크
        existing_application = Application.query.filter_by(user_id='current_user.id', job_id=job_id).first()
        if existing_application:
            api.abort(400, '이미 지원한 공고입니다.')  # 이미 지원한 공고면 400 응답
        
        # 지원 정보 저장
        new_application = Application(
            user_id='current_user.id',
            job_id=job_id,
            status='대기중',
            applied_at=datetime.utcnow()
        )
        db.session.add(new_application)
        db.session.commit()

        return {'message': '지원이 완료되었습니다.'}, 201  # 지원 성공 메시지 반환

#지원한 목록 가져오기 api
@application_api.route('/applications')
class ViewApplications(Resource):
    @api.doc(
        description='사용자가 지원한 모든 채용 공고 목록을 반환하는 API',
        responses={
            200: '지원한 채용 공고 목록 반환',
            401: '인증되지 않은 사용자',
            404: '지원한 공고가 없음'
        }
    )
    @api.marshal_with(application_model, as_list=True)  # 응답 형식 정의
    def get(self):
        """
        사용자가 지원한 모든 채용 공고 목록을 반환합니다.
        - 인증된 사용자만 이 API를 사용할 수 있습니다.
        """
        if not True:
            api.abort(401, '인증되지 않은 사용자')  # 인증되지 않은 사용자 처리

        # 사용자 ID를 기반으로 지원한 공고 목록 가져오기
        applications = db.session.query(
            Application,
            Job.title,
            Job.company
        ).join(Job, Application.job_id == Job.id).filter(Application.user_id == 'current_user.id').all()
        
        # 지원 목록이 없을 경우 404 반환
        if not applications:
            api.abort(404, '지원한 공고가 없습니다.')

        # 데이터 포맷팅 (응답용 리스트 형태로 변환)
        applications_list = [
            {
                "job_id": app.Application.job_id,
                "company": app.company,
                "title": app.title,
                "status": app.Application.status,
                "applied_at": app.Application.applied_at.strftime("%Y-%m-%d %H:%M:%S")
            } for app in applications
        ]
        
        return applications_list  # JSON 형식으로 반환

# 지원내역 취소
@application_api.route('/applications/<int:job_id>')
class CancelApplication(Resource):
    @api.doc(
        description='사용자가 특정 공고에 대해 제출한 지원을 취소합니다.',
        responses={
            200: '지원 취소 성공',
            400: '대기중이 아닌 지원은 취소할 수 없습니다.',
            404: '해당 공고에 대한 지원 내역을 찾을 수 없습니다.',
            500: '지원 취소 중 오류 발생'
        }
    )
    @api.param('job_id', '채용 공고 ID')
    @token_required
    def delete(self, current_user, job_id):
        # 사용자 ID와 job_id에 해당하는 지원 내역 찾기
        application = db.session.query(Application).join(Job, Application.job_id == job_id) \
            .filter(Application.user_id == current_user.id, Application.job_id == job_id).first()

        if not application:
            return jsonify({"message": "해당 공고에 대한 지원 내역을 찾을 수 없습니다."}), 404

        # 지원 상태가 '대기중'일 때만 취소 가능
        if application.status != '대기중':
            return jsonify({"message": "대기중인 지원만 취소할 수 있습니다."}), 400

        try:
            # 지원 내역 삭제
            db.session.delete(application)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            return jsonify({"message": "지원 취소 중 오류가 발생했습니다.", "error": str(e)}), 500

        return jsonify({"message": "지원이 취소되었습니다."}), 200

@application_api.route('/bookmarks')
class ToggleBookmark(Resource):
    @api.doc(
        description='사용자가 특정 공고에 대해 북마크를 추가하거나 제거합니다.',
        responses={
            200: '북마크가 제거되었습니다.',
            201: '북마크가 추가되었습니다.',
            404: '해당 공고를 찾을 수 없습니다.',
        }
    )
    @api.expect(bookmark_model)  # 요청 body에 대한 모델
    @token_required
    def post(self, current_user):
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

@application_api.route('/toggle_bookmark/<int:job_id>')
class ToggleBookmark(Resource):
    @api.doc(
        description='사용자가 특정 공고에 대해 북마크를 추가하거나 제거합니다.',
        responses={
            200: '북마크가 제거되었습니다.',
            201: '북마크가 추가되었습니다.',
            404: '해당 공고를 찾을 수 없습니다.',
        }
    )
    @api.param('job_id', '채용 공고 ID')  # URL 파라미터로 job_id 받기
    @token_required
    def post(self, current_user, job_id):
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

@application_api.route('/bookmarks')
class BookmarkedJobs(Resource):
    @api.doc(
        description='사용자가 북마크한 채용 공고 목록을 최신순으로 조회합니다.',
        responses={
            200: '북마크된 공고 목록을 성공적으로 반환합니다.',
            404: '북마크된 공고를 찾을 수 없습니다.'
        }
    )
    @api.param('page', '조회할 페이지 번호 (기본값: 1)', type=int)
    @api.param('per_page', '페이지당 공고 수 (기본값: 20)', type=int)
    @token_required
    def get(self, current_user):
        # 기본값 설정
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
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

        # 총 북마크 수 계산
        total_bookmarks = query.count()

        # 페이지네이션 적용
        bookmarked_jobs = query.offset(offset).limit(per_page).all()

        # 총 페이지 수 계산
        total_pages = (total_bookmarks // per_page) + (1 if total_bookmarks % per_page > 0 else 0)

        # 성공적으로 반환
        return jsonify({
            'jobs': [job._asdict() for job in bookmarked_jobs],
            'page': page,
            'per_page': per_page,
            'total_pages': total_pages,
            'total_jobs': total_bookmarks
        })


if __name__ == '__main__':
    app.run(debug=True)
