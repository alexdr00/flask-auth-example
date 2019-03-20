from peewee import Model, CharField
from config import Config


class User(Model):
    email = CharField(unique=True)
    password = CharField()

    class Meta:
        database = Config.mysql_db
