import time
from datetime import datetime
from flask.ext.sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class Submission(db.Model):
    __tablename__ = 'submissions'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    body = db.Column(db.String, nullable=False)
    created = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.Enum('approved', 'removed', 'unset', 'autoremoval', 'quietbanremoval'), default='unset')
    ip = db.Column(db.String)
    u_a = db.Column(db.String)

class IPBan(db.Model):
    __tablename__ = 'ipbans'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    ip = db.Column(db.String, nullable=False)
    ban_type = db.Column(db.Enum('quiet', 'public'))
    ban_note_private = db.Column(db.String)
    ban_note_public = db.Column(db.String)
    issued = db.Column(db.Integer, default=int(time.time()))
    duration = db.Column(db.Integer)
    active = db.Column(db.Boolean, default=True)

class Settings(db.Model):
    __tablename__ = 'settings'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    secret_key = db.Column(db.String)
    shown = db.Column(db.Boolean, default=False)
    regex_filter = db.Column(db.String, default="")