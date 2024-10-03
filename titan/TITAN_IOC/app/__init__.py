from flask import Flask
from models import db
import config

app = Flask(__name__)
app.config.from_object(config.Config)

db.init_app(app)

# Import routes after initializing the app
from routes import *
