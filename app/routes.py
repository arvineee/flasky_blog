from flask import render_template, url_for, redirect, flash, request
from app import app, bootstrap,db,login_manager
from app.models import User, Post
from app.forms import LoginForm, RegisterForm, PostForm,CommentForm
from flask_login import login_user, current_user, login_required,logout_user
from werkzeug.security import generate_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
import bleach
from flask_ckeditor.utils import cleanify
import os

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
            return redirect(url_for("index"))  # Redirect to a default route
        return func(*args, **kwargs)
    return wrapper



def check_ban(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated and current_user.is_authenticated and current_user.is_banned:
            flash("You are banned from accessing this feature. Contact the admin.", "danger")
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
def index():
    if current_user.is_banned:
        flash("Your account has been restricted. Please contact the admin.", "danger")
        return redirect(url_for("logout"))
    
    # Filter out posts by banned users and blocked posts
    posts = Post.query.join(User).filter(User.is_banned == False, Post.is_blocked == False).order_by(Post.id.desc()).all()

    return render_template('index.html', posts=posts)


@app.route("/login", methods=["POST", "GET"])
def login():
    form = LoginForm()
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data.strip()
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash(f'{user.username} logged in successfully', 'success')
            return redirect(url_for('index'))
        flash('Wrong Username or Password', 'danger')
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if form.validate_on_submit():
        username = form.username.data.strip()
        email = form.email.data.strip()
        password = form.password.data.strip()

        existing_user = User.query.filter_by(username=username).first()
        existing_email = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Username already used!', 'danger')
            return redirect(url_for('register'))
        elif existing_email:
            flash('Email already used!', 'danger')
            return redirect(url_for('register'))
        else:
            user = User(username=username, email=email)
            user.password_hash = generate_password_hash(password)
            db.session.add(user)
            db.session.commit()
            flash(f'{user.username}, registered successfully. Please Login', 'success')
            return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))



@app.route("/new_post", methods=["GET", "POST"])
@login_required
@check_ban
def new_post():
    if current_user.is_banned:
        flash("You are banned and cannot create posts. Contact the admin for further assistance.", "danger")
        return redirect(url_for("index"))

    form = PostForm()
    if request.method == "POST" and form.validate_on_submit():
        title = form.data['title'].strip()
        desc = form.data['desc'].strip()

        # Define allowed tags for a rich text experience
        allowed_tags = ['p', 'strong', 'em', 'a', 'ul', 'ol', 'li', 'br', 'u', 'i', 'b',
                        'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'blockquote', 'code', 'pre',
                        'img', 'hr', 'table', 'tr', 'th', 'td']
        allowed_attributes = {
            'a': ['href', 'title'],
            'img': ['src', 'alt', 'title'],
            'table': ['class'],
            'tr': ['class'],
            'th': ['class'],
            'td': ['class']
        }

        # Sanitize the CKEditor content
        sanitized_desc = bleach.clean(desc, tags=allowed_tags, attributes=allowed_attributes, strip=True)

        file = request.files.get('image')
        if not file or file.filename == "":
            flash('No selected file', 'warning')
            return redirect(request.url)

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            post = Post(title=title, desc=sanitized_desc, image_url=filename, author=current_user)
            db.session.add(post)
            db.session.commit()

            flash("New post created and published successfully", "success")
            return redirect(url_for("index"))

    return render_template("new_post.html", form=form)


@app.route('/see_more/<int:post_id>')
def see_more(post_id):
    form = CommentForm()
    post = Post.query.get_or_404(post_id)
    return render_template('see_more.html', post=post,form=form)

@app.route('/delete_post/<int:post_id>', methods=["POST"])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)

    # Ensure the current user is the author of the post
    if post.author != current_user:
        flash("You are not authorized to delete this post.", "danger")
        return redirect(url_for('index'))

    # Delete the post
    db.session.delete(post)
    db.session.commit()
    flash("Post has been deleted successfully.", "success")
    return redirect(url_for('index'))
