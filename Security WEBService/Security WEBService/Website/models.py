from . import db
from flask_login import UserMixin
from sqlalchemy.sql import func
import pyotp


class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    data = db.Column(db.String(10000))
    date = db.Column(db.DateTime(timezone=True), default=func.now())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True)
    first_name = db.Column(db.String(150))
    password = db.Column(db.String(150))
    otp_secret = db.Column(db.String(16), nullable=True)
    notes = db.relationship('Note')
    roles = db.relationship('Role', secondary='user_roles', backref=db.backref('users'))

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    permissions = db.relationship('Permission', secondary='role_permissions', backref=db.backref('roles'))

class Permission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
   

user_roles = db.Table('user_roles',
   db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
   db.Column('role_id', db.Integer, db.ForeignKey('role.id'))
)        

role_permissions = db.Table('role_permissions',
     db.Column('role_id', db.Integer, db.ForeignKey('role.id')),
     db.Column('permission_id', db.Integer, db.ForeignKey('permission.id'))
)