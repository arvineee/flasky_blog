from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from app.models import User, Post,Comment, TrafficStats,Announcement, NewsletterSubscriber,Like,Video
from app.forms import AdminActionForm,VideoForm
from app import db,app
from flask_mail import Message
from app import mail
from datetime import datetime
from werkzeug.security import generate_password_hash
from werkzeug.utils import secure_filename                  
import os
from functools import wraps
import bleach
from flask_ckeditor.utils import cleanify
from app.forms import LoginForm, RegisterForm, PostForm,CommentForm,ContactForm, ResetPasswordRequestForm, ResetPasswordForm

admin_bp = Blueprint('admin', __name__)

def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            flash("You need to log in to access this page.", "warning")
            return redirect(url_for("login"))
        if not current_user.is_admin:
            flash("You do not have the required permissions to access this page.", "danger")
            return redirect(url_for("index"))  # Redirect to a default route
        return func(*args, **kwargs)
    return wrapper

def check_ban(f):                                                            
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated and current_user.is_banned:
            flash("You are banned from accessing this feature. Contact the admin.", "danger")
            return redirect(url_for("index"))                                          
        return f(*args, **kwargs)
    return decorated_function


def allowed_file(filename, extensions=None):
    if not extensions:
        extensions = ['jpg', 'jpeg', 'png', 'gif']
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in extensions


def send_warning_email(user_email, message_body):
    msg = Message("Warning from Admin", recipients=[user_email])
    msg.body = message_body
    mail.send(msg)

# Admin dashboard
@admin_bp.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash("Access Denied!", "danger")
        return redirect(url_for('index'))

    users = User.query.all()
    posts = Post.query.all()
    return render_template('admin_dashboard.html', users=users, posts=posts)

# Admin action on user
@admin_bp.route('/admin/user/<int:user_id>/action', methods=['GET', 'POST'])
@login_required
def admin_user_action(user_id):
    if not current_user.is_admin:
        flash("Access Denied!", "danger")
        return redirect(url_for('index'))

    user = User.query.get_or_404(user_id)
    form = AdminActionForm()

    if form.validate_on_submit():
        if form.is_banned.data:
            user.is_banned = True
            flash(f"User {user.username} has been banned!", "success")
        if form.warning_message.data:
            user.warning_message = form.warning_message.data
            # Sending warning email
            msg = Message("Warning from Admin", recipients=[user.email])
            msg.body = f"Warning: {form.warning_message.data}"
            mail.send(msg)
            flash(f"Warning sent to {user.username}!", "success")

        db.session.commit()
        return redirect(url_for('admin.admin_dashboard'))

    return render_template('admin_user_action.html', user=user, form=form)

# Delete post
@admin_bp.route('/admin/post/<int:post_id>/delete', methods=['POST'])
@login_required
def admin_delete_post(post_id):

    if not current_user.is_admin:
        flash("Access Denied!", "danger")
        return redirect(url_for('index'))

    post = Post.query.get_or_404(post_id)
    db.session.delete(post)
    db.session.commit()
    flash("Post deleted successfully!", "success")
    return redirect(url_for('admin.admin_dashboard'))

# Block post
@admin_bp.route('/admin/post/<int:post_id>/block')
@login_required
def admin_block_post(post_id):
    if not current_user.is_admin:
        flash("Access Denied!", "danger")
        return redirect(url_for('index'))

    post = Post.query.get_or_404(post_id)
    post.is_blocked = True
    db.session.commit()
    flash("Post blocked successfully!", "success")
    return redirect(url_for('admin.admin_dashboard'))

# Unban user
@admin_bp.route('/admin/user/<int:user_id>/unban', methods=['GET', 'POST'])
@login_required
def admin_unban_user(user_id):
    if not current_user.is_admin:
        flash("Access Denied!", "danger")
        return redirect(url_for('index'))

    user = User.query.get_or_404(user_id)
    user.is_banned = False  # Unban the user
    db.session.commit()
    flash(f"User {user.username} has been unbanned!", "success")
    return redirect(url_for('admin.admin_dashboard'))

# Unblock post
@admin_bp.route('/admin/post/<int:post_id>/unblock', methods=['GET', 'POST'])
@login_required
def admin_unblock_post(post_id):
    if not current_user.is_admin:
        flash("Access Denied!", "danger")
        return redirect(url_for('index'))

    post = Post.query.get_or_404(post_id)
    post.is_blocked = False  # Unblock the post
    db.session.commit()
    flash("Post unblocked successfully!", "success")
    return redirect(url_for('admin.admin_dashboard'))


@admin_bp.route('/admin/traffic')
@login_required
def admin_traffic_stats():
    if not current_user.is_admin:
        flash("Access Denied!", "danger")
        return redirect(url_for('index'))

    # Fetch recent traffic data (last 30 days)
    from datetime import timedelta
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=30)
    traffic_stats = TrafficStats.query.filter(
        TrafficStats.timestamp.between(start_date, end_date)
    ).order_by(TrafficStats.timestamp.desc()).all()

    # Calculate statistics
    total_visitors = sum(stat.visitor_count for stat in traffic_stats)
    total_time_spent = sum(stat.total_time_spent for stat in traffic_stats)
    avg_time_per_visitor = total_time_spent / total_visitors if total_visitors > 0 else 0

    return render_template(
        'admin_traffic.html',
        traffic_stats=traffic_stats,
        total_visitors=total_visitors,
        total_time_spent=total_time_spent,
        avg_time_per_visitor=avg_time_per_visitor
        )

@admin_bp.route('/admin/announcement/create', methods=['GET', 'POST'])
@login_required
def create_announcement():
    if not current_user.is_admin:
        flash("Access Denied!", "danger")
        return redirect(url_for('index'))

    if request.method == 'POST':
        title = request.form.get('title')
        message = request.form.get('message')

        if title and message:
            announcement = Announcement(title=title, content=message, author_id=current_user.id)
            db.session.add(announcement)
            db.session.commit()

            # Notify subscribers
            subscribers = NewsletterSubscriber.query.filter_by(subscribed=True).all()
            for subscriber in subscribers:
                unsubscribe_link = url_for('newsletter.unsubscribe', subscriber_id=subscriber.id, _external=True)
                msg = Message(f"New Announcement: {title}", recipients=[subscriber.email])
                msg.body = f"{message}\n\nTo unsubscribe, click here: {unsubscribe_link}"
                mail.send(msg)

            flash("Announcement created and subscribers notified!", "success")
            return redirect(url_for('admin.admin_dashboard'))
        else:
            flash("Please fill out both the title and message fields.", "danger")

    return render_template('create_announcement.html')


@admin_bp.route('/admin/announcement/delete/<int:announcement_id>', methods=['POST'])
@login_required
def delete_announcement(announcement_id):
    if not current_user.is_admin:
        flash("Access Denied!", "danger")
        return redirect(url_for('index'))

    announcement = Announcement.query.get_or_404(announcement_id)

    try:
        db.session.delete(announcement)
        db.session.commit()
        flash("Announcement deleted successfully!", "success")
    except Exception as e:
        db.session.rollback()
        flash("An error occurred while deleting the announcement.", "danger")

    return redirect(url_for('admin.admin_dashboard'))


@admin_bp.route("/new_post", methods=["GET", "POST"])
@login_required
@admin_required
@check_ban
def new_post():
    if current_user.is_banned:
        flash("You are banned and cannot create posts. Contact the admin for further assistance.", "danger")
        return redirect(url_for("index"))

    form = PostForm()
    if form.validate_on_submit():
        try:
            title = form.title.data.strip()
            desc = form.desc.data.strip()
            category = form.category.data.strip()

            # Define allowed tags and attributes
            allowed_tags = [
                'p', 'strong', 'em', 'a', 'ul', 'ol', 'li', 'br', 'u', 'i', 'b',
                'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'blockquote', 'code', 'pre',
                'img', 'hr', 'table', 'tr', 'th', 'td'
            ]
            
            allowed_attributes = {
                'a': ['href', 'title'],
                'img': ['src', 'alt', 'title', 'style'],
                'table': ['class', 'border'],
                'tr': ['class'],
                'th': ['class', 'scope'],
                'td': ['class']
            }

            # Sanitize content
            sanitized_desc = bleach.clean(
                desc,
                tags=allowed_tags,
                attributes=allowed_attributes,
                strip=True
            )

            # Handle file upload
            file = form.image.data
            if not file or file.filename == '':
                flash('No image selected', 'warning')
                return redirect(request.url)

            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)

                # Create new post
                post = Post(
                    title=title,
                    desc=sanitized_desc,
                    category=category,
                    image_url=filename,
                    author=current_user
                )
                db.session.add(post)
                db.session.commit()

                flash("Post created successfully!", "success")
                return redirect(url_for("admin.admin_dashboard"))

        except Exception as e:
            db.session.rollback()
            flash(f"Error creating post: {str(e)}", "danger")
            app.logger.error(f"Post creation error: {str(e)}")

    return render_template("new_post.html", form=form)


@admin_bp.route('/see_more/<int:post_id>')
def see_more(post_id):
    form = CommentForm()
    post = Post.query.get_or_404(post_id)
    # Ensure the views count is initialized to 0 if it's None
    if post.views is None:
        post.views = 0
    # Increment the view count
    post.views += 1
    db.session.commit()  # Commit the change to the database
    comments = Comment.query.filter_by(post_id=post_id).all()
    return render_template('see_more.html', post=post, form=form, comments=comments, Like=Like)

@admin_bp.route('/edit_post/<int:post_id>', methods=['GET', 'POST'])
@login_required
@check_ban
def edit_post(post_id):
    if current_user.is_banned:
        flash("You are banned and cannot edit posts. Contact the admin for further assistance.", "danger")
        return redirect(url_for("index"))

    post = Post.query.get_or_404(post_id)
    # Check if the current user is the author or an admin
    if post.author != current_user and not current_user.is_admin:
        flash("You do not have permission to edit this post.", "danger")
        return redirect(url_for('index'))

    form = PostForm(obj=post)  # Populate the form with the post's data
    if request.method == "POST" and form.validate_on_submit():
        title = form.data['title'].strip()
        desc = form.data['desc'].strip()

        # Sanitize the CKEditor content
        allowed_tags = [
            'p', 'strong', 'em', 'a', 'ul', 'ol', 'li', 'br', 'u', 'i', 'b',
            'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'blockquote', 'code', 'pre',
            'img', 'hr', 'table', 'tr', 'th', 'td'
        ]
        allowed_attributes = {
            'a': ['href', 'title'],
            'img': ['src', 'alt', 'title'],
            'table': ['class'],
            'tr': ['class'],
            'th': ['class'],
            'td': ['class']
        }
        sanitized_desc = bleach.clean(desc, tags=allowed_tags, attributes=allowed_attributes, strip=True)

        # Handle image file upload if a new image is selected
        file = request.files.get('image')
        if file and file.filename != "":
            if allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                post.image_url = filename
            else:
                flash('File type not allowed.', 'warning')
                return redirect(request.url)

        # Update post details
        post.title = title
        post.desc = sanitized_desc
        db.session.commit()
        flash("Post updated successfully", "success")
        return redirect(url_for("index"))

    return render_template("edit_post.html", form=form, post=post)

@admin_bp.route('/search', methods=['GET', 'POST'])
def search():
    query = request.args.get('q', '').strip()  # Get the search keyword from the query string
    if not query:
        flash("Please enter a keyword to search.", "warning")
        return redirect(url_for('index'))

    # Search posts with titles containing the keyword (case insensitive)
    posts = Post.query.filter(Post.title.ilike(f'%{query}%')).all()

    if not posts:
        flash("No posts found matching your search query.", "info")

    return render_template('search_results.html', query=query, posts=posts)

@admin_bp.route("/upload_video", methods=["GET", "POST"])
@login_required
@check_ban
def upload_video():
    if current_user.is_banned:
        flash("You are banned and cannot upload videos. Contact the admin for further assistance.", "danger")
        return redirect(url_for("index"))

    form = VideoForm()  # Create a WTForm for video upload
    if request.method == "POST" and form.validate_on_submit():
        title = form.data['title'].strip()
        description = form.data['description'].strip()

        # Handle video file upload
        file = request.files.get('video')
        if not file or file.filename == "":
            flash("No video file selected.", "warning")
            return redirect(request.url)

        if allowed_file(file.filename, extensions=['mp4', 'mkv', 'avi', 'mov']):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['VIDEO_UPLOAD_FOLDER'], filename)
            file.save(file_path)

            # Save the video information
            video = Video(title=title, description=description, video_url=filename, author=current_user)
            db.session.add(video)
            db.session.commit()

            flash("Video uploaded successfully!", "success")
            return redirect(url_for("index"))
        else:
            flash("Invalid video format. Allowed formats: mp4, mkv, avi, mov.", "danger")
            return redirect(request.url)

    return render_template("upload_video.html", form=form)


@admin_bp.route("/videos")
def videos():
    videos = Video.query.order_by(Video.upload_time.desc()).all()  # Use upload_time instead of uploaded_at
    return render_template("videos.html", videos=videos)
