from flask import Flask
from flask_restx import Api, Resource, fields

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
test_api = api.namespace('test', description='테스트 관련 API')

# Swagger 모델 정의 (응답 형식)
hello_response = test_api.model('HelloResponse', {
    'message': fields.String(description='응답 메시지', example='Hello World!')
})

# 엔드포인트 정의
@test_api.route('/')
class Test(Resource):
    @test_api.doc(description="Hello World를 반환하는 간단한 API")
    @test_api.marshal_with(hello_response)  # Swagger 문서에 응답 형식 표시
    def get(self):
        """
        간단한 Hello World 반환 API
        """
        return {'message': 'Hello World!'}, 200


if __name__ == '__main__':
    app.run(debug=True)
