import os

class Config:
    SQLALCHEMY_DATABASE_URI = 'sqlite:///ioc_database.db'  # SQLite for local development
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = os.urandom(24)
