import os

class Config:
    SQLALCHEMY_DATABASE_URI = 'sqlite:///ioc_database.db'  # Main database (User IOCs)
    SQLALCHEMY_BINDS = {
        'codex': 'sqlite:///codex_db.db'  # Secondary database for Codex IOCs
    }
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = os.urandom(24)

