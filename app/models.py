from datetime import date
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app import db, login_manager
from datetime import datetime

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
    like_count = db.Column(db.Integer, default=0)
    comments = db.relationship('Comment', backref='post', lazy='dynamic')

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.String(), default=date.today)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('comments', lazy=True))

class TrafficStats(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    endpoint = db.Column(db.String(255))  # Track which route was visited
    visitor_ip = db.Column(db.String(45))  # For IPv4/IPv6
    visitor_count = db.Column(db.Integer, nullable=False, default=1)
    total_time_spent = db.Column(db.Float, nullable=False, default=0)  # Time spent in seconds
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)



class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('likes', lazy=True))
    post = db.relationship('Post', backref=db.backref('likes', lazy=True))

    __table_args__ = (db.UniqueConstraint('user_id', 'post_id', name='_user_post_uc'),)


@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))
