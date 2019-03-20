from lib.hash_salt_pwd import hash_password, match_passwords
from flask import Blueprint, request
from flask_restful import Resource, Api
import flask_jwt_extended as jwt
from config import Config
from models import User

blacklist = Config.token_blacklist


def create_token(identity):
    access_token = jwt.create_access_token(identity=identity)
    refresh_token = jwt.create_refresh_token(identity=identity)

    return {'refresh_token': refresh_token, 'access_token': access_token}


class UserRegistration(Resource):
    def post(self):
        data = request.get_json()
        password = data['password']
        password_hashed = hash_password(password)
        data['password'] = password_hashed

        if User.get_or_none(User.email == data['email']):
            return {'message': 'That user already exists'}, 400

        token = create_token(data['email'])

        user_created = User(**data)
        user_created.save()

        return {
            'message': 'User created successfully',
            'access_token': token['access_token'],
            'refresh_token': token['refresh_token']
        }, 201


class UserLogin(Resource):
    def post(self):
        data = request.get_json()
        current_user = User.get_or_none(User.email == data['email'])

        if not current_user:
            return {'message': 'Wrong credentials'}, 202

        token = create_token(data['email'])

        if match_passwords(current_user.password, data['password']):
            return {
               'message': 'Logged in successfully',
               'access_token': token['access_token'],
               'refresh_token': token['refresh_token']
            }, 200

        else:
            return {'message': 'Wrong credentials'}, 202


class UserLogoutAccess(Resource):
    @jwt.jwt_required
    def post(self):
        jti = jwt.get_raw_jwt()['jti']
        blacklist.add(jti)

        return {'message': 'Logged out'}, 200


class UserLogoutRefresh(Resource):
    @jwt.jwt_refresh_token_required
    def post(self):
        jti = jwt.get_raw_jwt()['jti']
        blacklist.add(jti)

        return {'message': 'Logged out'}, 200


class TokenRefresh(Resource):
    @jwt.jwt_refresh_token_required
    def post(self):
        current_user = jwt.get_jwt_identity()
        access_token = jwt.create_access_token(identity=current_user)

        return {'access_token': access_token}


class SecretResource(Resource):
    @jwt.jwt_required
    def get(self):
        return {'message': 'You accessed a protected resource!'}


user_api = Blueprint('resources.user', __name__)

api = Api(user_api)

api.add_resource(UserRegistration, '/registration')
api.add_resource(UserLogin, '/login')
api.add_resource(UserLogoutAccess, '/logout/access')
api.add_resource(UserLogoutRefresh, '/logout/refresh')
api.add_resource(TokenRefresh, '/token/refresh')
api.add_resource(SecretResource, '/secret')
