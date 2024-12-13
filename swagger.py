from flask import Flask
from flask_restx import Api, Resource, reqparse

app = Flask(__name__)

api = Api(app, version='1.0', title='API 문서', description='Swagger 문서', doc="/api-docs")

test_api = api.namespace('test', description='조회 API')



@test_api.route('/')
class Test(Resource):
    def get(self):
    	return 'Hello World!'


if __name__ == '__main__':
    app.run()
