from flask import Flask
from flask_jwt_extended import JWTManager
from models import User
from config import Config

from resources.users import user_api

URL_PREFIX = '/api/v1'

app = Flask(__name__)

# JWT Config
app.config['JWT_SECRET_KEY'] = Config.jwt_secret
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']

jwt = JWTManager(app)
db = Config.mysql_db


@jwt.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    jti = decrypted_token['jti']
    is_in_blacklist = jti in Config.blacklist

    return is_in_blacklist


# SQL connection
@app.before_request
def _db_connect():
    db.connect()


@app.teardown_request
def _db_close(exc):
    if not db.is_closed():
        db.close()


db.create_tables([User])

app.register_blueprint(user_api, url_prefix=URL_PREFIX)


def main():
    app.run(port=5000, debug=True)


if __name__ == '__main__':
    main()
