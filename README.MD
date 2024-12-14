(초간단 실행법) 윈도우에서 파이썬과 pip가 잘 작동될 때
1. pip install -r requirements.txt

2. python server.py

(우분투에서 돌릴때)
1. sudo apt install python3-venv
2. python3 -m venv myenv
3. source myenv/bin/activate
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


직무데이터_동기화_함수.txt의 코드를
db.init_app(app)

다음에 
server.py에 복사해서 서버를 한번 실행시키면 된다.

python server.py

