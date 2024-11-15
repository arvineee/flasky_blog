from datetime import date
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app import db, login_manager

class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False, unique=True, index=True)
    email = db.Column(db.String(150), nullable=False, unique=True, index=True)
    password_hash = db.Column(db.String(256))
    is_admin = db.Column(db.Boolean, default=False)
    date_r = db.Column(db.String(), default=date.today)
    is_banned = db.Column(db.Boolean, default=False)
    warning_message = db.Column(db.String(500), nullable=True)
    posts = db.relationship('Post', backref='author', lazy='dynamic')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Post(db.Model):
    __tablename__ = 'post'
    id = db.Column(db.Integer, primary_key=True, index=True)
    title = db.Column(db.String(100), nullable=False)
    desc = db.Column(db.Text, nullable=False)
    date_pub = db.Column(db.String(), default=date.today)
    image_url = db.Column(db.String(), nullable=True)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    is_blocked = db.Column(db.Boolean, default=False)

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))
