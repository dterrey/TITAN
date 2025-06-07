from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class IOC(db.Model):
    __tablename__ = 'ioc'
    id = db.Column(db.Integer, primary_key=True)
    indicator = db.Column(db.String(255), nullable=False)
    type = db.Column(db.String(50), nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())
    tag = db.Column(db.String(255), nullable=True)

class CodexIOC(db.Model):
    __bind_key__ = 'codex'
    __tablename__ = 'codex_ioc'
    id = db.Column(db.Integer, primary_key=True)
    indicator = db.Column(db.String, nullable=False)
    type = db.Column(db.String, nullable=False)
    parsed_file = db.Column(db.String, nullable=False)  # Track which file the IOC came from
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())


