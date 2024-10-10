from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class IOC(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    indicator = db.Column(db.String(255), nullable=False)
    type = db.Column(db.String(50), nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())
    tag = db.Column(db.String(255), nullable=True)
    new_column = db.Column(db.String(255), nullable=True)  # Temporary column
