(초간단 실행법) 
윈도우에서 파이썬과 pip가 잘 작동될 때
1. pip install -r requirements.txt

2. python server.py

(우분투에서 돌릴때)
1. sudo apt install python3-venv
2. python3 -m venv myenv
3. source myenv/bin/activate
프로젝트 폴더 가서(cd /web_task03)
4. pip install -r requirements.txt
5. python server.py

Jcloud 땜시 포트를 3000번으로 바꿔놓음


(db가 없을 떄)
프로젝트 폴더에서 터미널에 
pip install -r requirements.txt

필요한 모듈 설치가 완료된다.


webcrawling 에 있는
webcrawling.py를 python webcrawling.py
를 입력해 실행시킨다.
saramin_jobs.db가 생기면


직무데이터_동기화_함수.txt의 코드를 server.py가서
db.init_app(app)

다음에 복사해서 서버를 한번 실행시키면 된다.

python server.py



-정리-
webcrawling폴더에서 크롤링하면, 크롤링한 데이터를
server.py 실행할 때 유저 데이터베이스 테이블과 합치게 됨(직무데이터_동기화_함수.txt)


에러처리
Error: module 'jwt' has no attribute 'encode'

로그인시 저 에러가 뜨게 된다면
pip uninstall jwt
pip uninstall PyJWT
pip install PyJWT

하고 다시 서버를 키면 된다.