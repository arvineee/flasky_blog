
from datetime import date, datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app import db, login_manager

# ---------------------- User Model ----------------------
class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False, unique=True, index=True)
    email = db.Column(db.String(150), nullable=False, unique=True, index=True)
    password_hash = db.Column(db.String(256))
    is_admin = db.Column(db.Boolean, default=False)
    date_r = db.Column(db.DateTime, default=datetime.utcnow)
    is_banned = db.Column(db.Boolean, default=False)
    warning_message = db.Column(db.String(500), nullable=True)

    posts = db.relationship('Post', backref='author', lazy='dynamic')
    comments = db.relationship('Comment', backref='user', lazy=True)
    likes = db.relationship('Like', backref='user', lazy=True)
    announcements = db.relationship('Announcement', backref='author', lazy=True)
    videos = db.relationship('Video', backref='author', lazy='dynamic')
    api_keys = db.relationship('ApiKey', backref='user', lazy='dynamic')
    ad_contents = db.relationship('AdContent', backref='advertiser', lazy='dynamic')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_avatar_url(self, size=32):
        from app.utils import get_avatar_url
        return get_avatar_url(self.email, self.username, size)

# ---------------------- Category Model ----------------------
class Category(db.Model):
    __tablename__ = 'category'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    parent_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=True)

    children = db.relationship(
        'Category',
        backref=db.backref('parent', remote_side=[id]),
        lazy='dynamic'
    )
    posts = db.relationship('Post', backref='category_obj', lazy='dynamic')

    def __repr__(self):
        return f'<Category {self.name}>'

# ---------------------- Post Model ----------------------
class Post(db.Model):
    __tablename__ = 'post'
    id = db.Column(db.Integer, primary_key=True, index=True)
    title = db.Column(db.String(100), nullable=False)
    desc = db.Column(db.Text, nullable=False)
    date_pub = db.Column(db.DateTime, default=datetime.utcnow)
    image_url = db.Column(db.String(), nullable=True)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'))
    is_blocked = db.Column(db.Boolean, default=False)
    views = db.Column(db.Integer, default=0)
    like_count = db.Column(db.Integer, default=0)

    comments = db.relationship('Comment', backref='post', lazy='dynamic', cascade='all, delete-orphan')
    likes = db.relationship('Like', backref='post', lazy='dynamic', cascade='all, delete-orphan')

    @property
    def comment_count(self):
        return self.comments.count()

    def __repr__(self):
        return f'<Post {self.title} by {self.author.username} on {self.date_pub}>'

# ---------------------- Comment Model ----------------------
class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.String(), default=date.today)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)

    def delete(self):
        db.session.delete(self)
        db.session.commit()

# ---------------------- Traffic Stats ----------------------
class TrafficStats(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    endpoint = db.Column(db.String(255))
    visitor_ip = db.Column(db.String(45))
    visitor_count = db.Column(db.Integer, nullable=False, default=1)
    total_time_spent = db.Column(db.Float, nullable=False, default=0)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

# ---------------------- Like Model ----------------------
class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (db.UniqueConstraint('user_id', 'post_id', name='_user_post_uc'),)

# ---------------------- Newsletter Subscriber ----------------------
class NewsletterSubscriber(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), nullable=False, unique=True, index=True)
    subscribed_on = db.Column(db.DateTime, default=datetime.utcnow)
    subscribed = db.Column(db.Boolean, default=True)

# ---------------------- Announcement ----------------------
class Announcement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f'<Announcement {self.title}>'

# ---------------------- Video Model ----------------------
class Video(db.Model):
    __tablename__ = 'video'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    video_url = db.Column(db.String(), nullable=False)
    upload_time = db.Column(db.DateTime, default=datetime.utcnow)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f'<Video {self.title} by {self.author.username} on {self.upload_time}>'

# ---------------------- User Loader ----------------
@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

# ---------------------- Ads.txt Model ---------------
class AdsTxt(db.Model):
    __tablename__ = 'ads_txt'
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow)
    updated_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    updater = db.relationship('User', backref='ads_txt_updates')

# ---------------------- Api model ----------------------
class ApiKey(db.Model):
    __tablename__ = 'api_key'
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(64), unique=True, nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    permissions = db.Column(db.String(500), default='post:create')

    

# ---------------------- Ad/Sponsored Content Model ----------------------
class AdContent(db.Model):
    __tablename__ = 'ad_content'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    advertiser_name = db.Column(db.String(100), nullable=False)
    advertiser_email = db.Column(db.String(150), nullable=False)
    advertiser_website = db.Column(db.String(200), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    start_date = db.Column(db.DateTime, default=datetime.utcnow)
    end_date = db.Column(db.DateTime, nullable=True)
    price = db.Column(db.Float, nullable=True)
    placement = db.Column(db.String(50), default='sidebar')
    clicks = db.Column(db.Integer, default=0)
    impressions = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    advertiser_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

    def __repr__(self):
        return f'<AdContent {self.title} by {self.advertiser_name}>'
