from flask import render_template, url_for, redirect, flash, request,send_file,jsonify,Blueprint,current_app,abort,make_response
from app import  bootstrap,db,login_manager,mail
from app.models import User, Post, Comment, Like, User,Announcement,Category,AdsTxt,NewsletterSubscriber
from app.forms import LoginForm, RegisterForm, PostForm,CommentForm,ContactForm, ResetPasswordRequestForm, ResetPasswordForm,SubscribeForm
from flask_login import login_user, current_user, login_required,logout_user
from werkzeug.security import generate_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
import bleach
from flask_ckeditor.utils import cleanify
import os
from flask_mail import Message
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from datetime import timedelta
from app.utils import get_recommended_posts


main = Blueprint('main', __name__)



ALLOWED_EXTENSIONS = { 'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS



def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            flash("You need to log in to access this page.", "warning")
            return redirect(url_for("login"))
        if not current_user.admin:
            flash("You do not have the required permissions to access this page.", "danger")
            return redirect(url_for("main.index"))  # Redirect to a default route
        return func(*args, **kwargs)
    return wrapper



def check_ban(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated and current_user.is_banned:
            flash("You are banned from accessing this feature. Contact the admin.", "danger")
            return redirect(url_for("main.index"))
        return f(*args, **kwargs)
    return decorated_function


@main.route('/')
def index():
    # Check if the current user is authenticated and banned
    if current_user.is_authenticated and current_user.is_banned:
        flash("Your account has been restricted. Please contact the admin.", "danger")
        return redirect(url_for("main.logout"))

    form = SubscribeForm()
    
    # Get the current page from request args or default to page 1
    page = request.args.get('page', 1, type=int)
    
    # Define how many posts to show per page
    per_page = 6
    
    # Get the active tab from request args or default to 'recent'
    tab = request.args.get('tab', 'recent')
    
    # Base query for posts (filter out banned users and blocked posts)
    base_query = Post.query.join(User).filter(
        User.is_banned == False, 
        Post.is_blocked == False
    )
    
    # Apply sorting based on the selected tab
    if tab == 'popular':
        posts_query = base_query.order_by(Post.like_count.desc(), Post.views.desc())
    else:  # recent is default
        posts_query = base_query.order_by(Post.date_pub.desc())
    
    # Fetch posts with pagination
    pagination = posts_query.paginate(page=page, per_page=per_page, error_out=False)
    posts = pagination.items  # This is the actual list of posts
    
    # Fetch featured posts for carousel (most recent 3 posts)
    featured_posts = base_query.order_by(Post.date_pub.desc()).limit(3).all()
    
    # Fetch announcements, limit to the latest 5
    announcements = Announcement.query.order_by(Announcement.date_created.desc()).limit(5).all()
    
    # Fetch trending categories (top 5 categories by post count)
    trending_categories = db.session.query(
        Category, 
        db.func.count(Post.id).label('post_count')
    ).join(Post).group_by(Category.id).order_by(db.func.count(Post.id).desc()).limit(5).all()
    
    # Get recommended posts
    recommended_posts = get_recommended_posts()

    # Render the index page with posts and announcements
    return render_template('index.html', 
                         posts=posts,  # Now this is a list, not a pagination object
                         pagination=pagination,  # Pass the pagination object separately
                         featured_posts=featured_posts,
                         announcements=announcements,
                         recommended_posts=recommended_posts,
                         trending_categories=trending_categories,
                         active_tab=tab,
                           form=form)


@main.route("/login", methods=["POST", "GET"])
def login():
    form = LoginForm()
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data.strip()
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user,remember=True,duration=timedelta(days=1))
            flash(f'{user.username} logged in successfully', 'success')
            return redirect(url_for('main.index'))
        flash('Wrong Username or Password', 'danger')
    return render_template('login.html', form=form)

@main.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    if form.validate_on_submit():
        username = form.username.data.strip()
        email = form.email.data.strip()
        password = form.password.data.strip()

        existing_user = User.query.filter_by(username=username).first()
        existing_email = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Username already used!', 'danger')
            return redirect(url_for('main.register'))
        elif existing_email:
            flash('Email already used!', 'danger')
            return redirect(url_for('main.register'))
        else:
            user = User(username=username, email=email)
            user.password_hash = generate_password_hash(password)
            db.session.add(user)
            db.session.commit()
            flash(f'{user.username}, registered successfully. Please Login', 'success')
            return redirect(url_for('main.login'))
    return render_template('register.html', form=form)

@main.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.login'))



@main.route('/delete_post/<int:post_id>', methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)

    # Allow post deletion for admin or the post author
    if not (post.author == current_user or current_user.is_admin):
        flash("You are not authorized to delete this post.", "danger")
        return redirect(url_for('main.index'))

    db.session.delete(post)
    db.session.commit()
    flash("Post has been deleted successfully.", "success")
    return redirect(url_for('main.index'))

@main.route('/share_post/<int:post_id>')
@login_required
def share_post(post_id):
    post = Post.query.get_or_404(post_id)
    return render_template('share_post.html', post=post)


@main.route('/add_comment/<int:post_id>', methods=['POST'])
@login_required
def add_comment(post_id):
    form = CommentForm()
    if form.validate_on_submit():
        comment = Comment(content=form.comment.data, user_id=current_user.id, post_id=post_id)
        db.session.add(comment)
        db.session.commit()
        flash('Your comment has been added!', 'success')
    else:
        flash('Error adding comment. Please try again.', 'danger')
    return redirect(url_for('admin.see_more', post_id=post_id))


@main.route('/like_post/<int:post_id>', methods=['POST'])
@login_required
def like_post(post_id):
    post = Post.query.get_or_404(post_id)
    existing_like = Like.query.filter_by(user_id=current_user.id, post_id=post_id).first()

    # Initialize like_count if None
    if post.like_count is None:
        post.like_count = 0

    # Toggle like state
    if existing_like:
        db.session.delete(existing_like)
        post.like_count -= 1
        action = "unliked"
    else:
        new_like = Like(user_id=current_user.id, post_id=post_id)
        db.session.add(new_like)
        post.like_count += 1
        action = "liked"

    db.session.commit()

    # Return JSON for AJAX requests
    return jsonify({
        'status': 'success',
        'action': action,
        'like_count': post.like_count,
        'post_id': post_id
    })

@main.route('/policy')
def policy():
    return render_template('policy.html')

@main.route('/privacy_policy')
def privacy_policy():
    return render_template('privacy_policy.html')

@main.route('/contact', methods=['GET', 'POST'])
def contact():
    form = ContactForm()
    if form.validate_on_submit():

        msg = Message("Arval-Blog Contact Submission",
              sender=form.email.data,
              recipients=[current_app.config['MAIL_USERNAME']])

        body = f"""
Dear Arval-Blog Team,

You have received a new contact form submission from:

Name: {form.name.data}
Email: {form.email.data}

Message:
{form.message.data}

Best regards,
Arval-Blog Contact System
"""

        # Set the body directly to the Message object, without using MIME objects
        msg.body = body.strip()  # .strip() to remove leading/trailing whitespace

        mail.send(msg)
        flash('Your message has been sent successfully.', 'success')
        return redirect(url_for('main.index'))
    return render_template('contact.html', form=form)


@main.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        # Initialize serializer for token generation
        serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])

        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = serializer.dumps(user.email, salt='password-reset-salt')
            msg = Message('Password Reset Request',
                          sender=app.config['MAIL_USERNAME'],
                          recipients=[user.email])
            link = url_for('reset_password', token=token, _external=True)
            msg.body = f'Here is your password reset link: {link}'
            mail.send(msg)
            flash('An email with instructions to reset your password has been sent.', 'info')
        return redirect(url_for('main.login'))
    return render_template('reset_password_request.html', form=form)

@main.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=3600)
    except SignatureExpired:
        flash('The password reset link has expired. Please request a new one.', 'warning')
        return redirect(url_for('main.reset_password_request'))
    except Exception:
        flash('Invalid reset link. Please try again.', 'danger')
        return redirect(url_for('main.reset_password_request'))

    user = User.query.filter_by(email=email).first()
    if not user:
        flash('Invalid reset request.', 'warning')
        return redirect(url_for('main.index'))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        db.session.commit()
        flash('Your password has been reset successfully!', 'success')
        return redirect(url_for('main.login'))
    return render_template('reset_password.html', form=form)


@main.route('/announcement/<int:announcement_id>')
@login_required
def announcement_detail(announcement_id):
    announcement = Announcement.query.get_or_404(announcement_id)
    return render_template('announcement_detail.html', announcement=announcement)
@login_required
@main.route('/ads.txt')
def serve_ads_txt():
    # Get the latest ads.txt entry
    ads_txt = AdsTxt.query.order_by(AdsTxt.last_updated.desc()).first()
    
    if ads_txt:
        # Create a response with the ads.txt content
        response = make_response(ads_txt.content)
        response.mimetype = 'text/plain'
        response.headers['Cache-Control'] = 'public, max-age=3600'  # Cache for 1 hour
        return response
    else:
        # Fallback to default content or 404
        default_content = "google.com, pub-2038759698856668, DIRECT, f08c47fec0942fa0"
        response = make_response(default_content)
        response.mimetype = 'text/plain'
        return response

@main.route('/delete_comment/<int:comment_id>', methods=['POST'])
@login_required
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    post_id = comment.post_id

    if comment.user == current_user or current_user.is_admin:
        db.session.delete(comment)   
        db.session.commit()
        flash('Comment deleted successfully.', 'success')
    else:
        flash('You are not authorized to delete this comment.', 'danger')

    return redirect(url_for('admin.see_more', post_id=post_id))


@login_required
@check_ban
@main.route("/category/<int:category_id>")
def category_posts(category_id):
    # Get the category
    category = Category.query.get_or_404(category_id)

    # Fetch posts in this category (and optionally in its subcategories)
    posts = Post.query.filter_by(category_id=category.id).order_by(Post.date_pub.desc()).all()

    return render_template("category_posts.html", category=category, posts=posts)

@main.route('/unsubscribe/<email>')
def unsubscribe_newsletter(email):
    subscriber = NewsletterSubscriber.query.filter_by(email=email).first()

    if subscriber:
        subscriber.subscribed = False
        db.session.commit()
        flash("You have been unsubscribed from our newsletter.", "success")
    else:
        flash("Email not found in our subscription list.", "warning")

    return redirect(url_for('main.index'))



