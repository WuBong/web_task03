import sqlite3
import requests
from bs4 import BeautifulSoup
import datetime

# SQLite 데이터베이스 연결
conn = sqlite3.connect('saramin_jobs.db')
cursor = conn.cursor()

# 테이블 생성 (없으면 생성)
cursor.execute('''
CREATE TABLE IF NOT EXISTS jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    today TEXT,
    title TEXT UNIQUE,  -- title을 UNIQUE로 설정
    company TEXT,
    url TEXT,
    deadline TEXT,
    location TEXT,
    experience TEXT,
    requirement TEXT,
    jobtype TEXT,
    jobday TEXT
)
''')
conn.commit()

# 키워드와 페이지 수 입력받기
keyword = input("키워드를 입력하세요 : ")
allPage = input("몇 페이지까지 추출하시겠어요 ?")

# 페이지별 데이터 크롤링
for page in range(1, int(allPage) + 1):
    soup = requests.get(
        f'https://www.saramin.co.kr/zf_user/search?searchword={keyword}&go=&flag=n&searchMode=1&searchType=search&search_done=y&search_optional_item=n&recruitPage={page}&recruitSort=relation&recruitPageCount=100',
        headers={'User-Agent': 'Mozilla/5.0'}
    )
    html = BeautifulSoup(soup.text, 'html.parser')
    jobs = html.select('div.item_recruit')

    for job in jobs:
        try:
            today = datetime.datetime.now().strftime('%Y-%m-%d')
            title = job.select_one('a')['title'].strip().replace(',', '')
            company = job.select_one('div.area_corp > strong > a').text.strip()
            url = 'https://www.saramin.co.kr' + job.select_one('a')['href']
            deadline = job.select_one('span.date').text.strip()
            location = job.select('div.job_condition > span')[0].text.strip()
            experience = job.select('div.job_condition > span')[1].text.strip()
            requirement = job.select('div.job_condition > span')[2].text.strip()
            jobtype = job.select('div.job_condition > span')[3].text.strip()
            jobday = job.select('div.job_sector > span')[0].text.strip()

            # 중복 확인
            cursor.execute('SELECT COUNT(*) FROM jobs WHERE title = ?', (title,))
            result = cursor.fetchone()

            # 중복된 제목이 없으면 데이터 삽입
            if result[0] == 0:
                cursor.execute('''
                INSERT INTO jobs (today, title, company, url, deadline, location, experience, requirement, jobtype, jobday)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (today, title, company, url, deadline, location, experience, requirement, jobtype, jobday))
                conn.commit()

                print(f"저장 완료: {title}")
            else:
                print(f"중복된 제목: {title}")

        except Exception as e:
            print(f"오류 발생: {e}")
            continue

# 연결 종료
conn.close()
