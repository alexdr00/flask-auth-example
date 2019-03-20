import os
from dotenv import load_dotenv
from playhouse.db_url import connect
load_dotenv()


class Config:
    db_uri = os.getenv('DB_URI')
    token_blacklist = set()
    mysql_db = connect(db_uri)
    jwt_secret = os.getenv('JWT_SECRET')
