import os
import bleach
import logging
from functools import wraps
from geoip2.errors import AddressNotFoundError
from datetime import datetime
from werkzeug.utils import secure_filename
from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app, jsonify
from flask_login import login_required, current_user
from flask_mail import Message
from app.utils import get_recommended_posts
from app import db, mail, csrf
from app.models import User, Post, Comment, TrafficStats, Announcement, NewsletterSubscriber, Like, Video, Category, AdsTxt, NewsletterSubscriber, ApiKey
from app.forms import (
    AdminActionForm, VideoForm, LoginForm, RegisterForm, PostForm, CommentForm,
    ContactForm, ResetPasswordRequestForm, ResetPasswordForm, AnnouncementForm, AdsTxtForm, NewsletterForm, CategoryForm
)
from .ddos_protection import ddos_protection
from app.utils import allowed_file
from datetime import datetime, timedelta
import secrets
import json

admin_bp = Blueprint('admin', __name__)
logger = logging.getLogger(__name__)

def is_ajax_request():
    return request.headers.get('X-Requested-With') == 'XMLHttpRequest'

def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            if is_ajax_request():
                return jsonify({'success': False, 'message': 'You need to log in to access this page.'}), 401
            flash("You need to log in to access this page.", "warning")
            return redirect(url_for("main.login"))
        if not current_user.is_admin:
            if is_ajax_request():
                return jsonify({'success': False, 'message': 'You do not have the required permissions to access this page.'}), 403
            flash("You do not have the required permissions to access this page.", "danger")
            return redirect(url_for("main.index"))
        return func(*args, **kwargs)
    return wrapper

def check_ban(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated and current_user.is_banned:
            if is_ajax_request():
                return jsonify({'success': False, 'message': 'You are banned from accessing this feature. Contact the admin.'}), 403
            flash("You are banned from accessing this feature. Contact the admin.", "danger")
            return redirect(url_for("main.index"))
        return f(*args, **kwargs)
    return decorated_function

def send_warning_email(user_email, message_body):
    msg = Message("Warning from Admin", recipients=[user_email])
    msg.body = message_body
    mail.send(msg)

# ---------------------- Admin Dashboard ----------------------
@admin_bp.route('/dashboard')
@login_required
@admin_required
def admin_dashboard():
    # Get user search query and filter
    user_search_query = request.args.get('q', '')
    user_filter_type = request.args.get('filter', 'all')
    
    # Get post search query and filter
    post_search_query = request.args.get('post_q', '')
    post_filter_type = request.args.get('post_filter', 'all')

    # Start with base query for users
    users_query = User.query

    # Apply user search filter if provided
    if user_search_query:
        users_query = users_query.filter(
            (User.username.ilike(f'%{user_search_query}%')) | 
            (User.email.ilike(f'%{user_search_query}%'))
        )

    # Apply user additional filters
    if user_filter_type == 'admins':
        users_query = users_query.filter(User.is_admin == True)
    elif user_filter_type == 'banned':
        users_query = users_query.filter(User.is_banned == True)
    elif user_filter_type == 'active':
        users_query = users_query.filter(User.is_banned == False)

    # Order and get all users
    users = users_query.order_by(User.date_r.desc()).all()

    # Start with base query for posts
    posts_query = Post.query.join(User).filter(User.is_banned == False)

    # Apply post search filter if provided
    if post_search_query:
        posts_query = posts_query.filter(
            (Post.title.ilike(f'%{post_search_query}%')) |
            (Post.desc.ilike(f'%{post_search_query}%'))
        )

    # Apply post additional filters
    if post_filter_type == 'blocked':
        posts_query = posts_query.filter(Post.is_blocked == True)
    elif post_filter_type == 'active':
        posts_query = posts_query.filter(Post.is_blocked == False)

    # Order and get all posts
    posts = posts_query.order_by(Post.date_pub.desc()).all()

    # Get other statistics
    categories = Category.query.all()
    banned_users_count = User.query.filter_by(is_banned=True).count()
    subscriber_count = NewsletterSubscriber.query.filter_by(subscribed=True).count()
    api_keys_count = ApiKey.query.filter_by(is_active=True).count()

    # Calculate posts created via API today
    today = datetime.utcnow().date()
    api_posts_today = Post.query.filter(
        Post.author.has(User.api_keys.any()),
        db.func.date(Post.date_pub) == today
    ).count()

    # Calculate posts created via API this week
    week_ago = datetime.utcnow() - timedelta(days=7)
    api_posts_week = Post.query.filter(
        Post.author.has(User.api_keys.any()),
        Post.date_pub >= week_ago
    ).count()

    # Count active API users
    active_api_users = User.query.filter(
        User.api_keys.any(ApiKey.is_active == True),
        User.posts.any(Post.date_pub >= week_ago)
    ).count()

    # Placeholder for API errors
    api_errors = 0

    # Get admin's country based on IP with better error handling
    admin_country = "Unknown"
    try:
        # Use the GeoIP reader from the app
        if hasattr(current_app, 'geoip_reader') and current_app.geoip_reader is not None:
            # Get the client IP address
            client_ip = request.remote_addr

            # Handle localhost/private IP addresses
            if client_ip in ['127.0.0.1', 'localhost'] or client_ip.startswith('192.168.') or client_ip.startswith('10.'):
                admin_country = "Local Network"
            else:
                # Try to get country from GeoIP
                response = current_app.geoip_reader.country(client_ip)
                admin_country = response.country.name
        else:
            admin_country = "GeoIP Not Configured"

    except AddressNotFoundError:
        admin_country = "IP Not Found in Database"
    except ValueError as e:
        logger.error(f"Invalid IP address format: {e}")
        admin_country = "Invalid IP"
    except Exception as e:
        logger.error(f"Error determining country: {str(e)}")
        admin_country = "Error"

    return render_template('admin_dashboard.html',
                         users=users,
                         posts=posts,
                         categories=categories,
                         subscriber_count=subscriber_count,
                         banned_users_count=banned_users_count,
                         api_keys_count=api_keys_count,
                         api_posts_today=api_posts_today,
                         api_posts_week=api_posts_week,
                         active_api_users=active_api_users,
                         api_errors=api_errors,
                         admin_country=admin_country)

# ---------------------- User Management ----------------------
@admin_bp.route('/user/<int:user_id>/action', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_user_action(user_id):
    user = User.query.get_or_404(user_id)
    form = AdminActionForm()

    if form.validate_on_submit():
        message = ""
        if form.is_banned.data:
            user.is_banned = True
            message = f"User {user.username} has been banned!"
        if form.warning_message.data:
            user.warning_message = form.warning_message.data
            msg = Message("Warning from Admin", recipients=[user.email])
            msg.body = f"Warning: {form.warning_message.data}"
            mail.send(msg)
            message = f"Warning sent to {user.username}!"

        db.session.commit()
        
        if is_ajax_request():
            return jsonify({'success': True, 'message': message})
        
        flash(message, "success")
        return redirect(url_for('admin.admin_dashboard'))

    return render_template('admin_user_action.html', user=user, form=form)

@admin_bp.route('/user/<int:user_id>/unban', methods=['POST'])
@login_required
@admin_required
def admin_unban_user(user_id):
    try:
        user = User.query.get_or_404(user_id)
        user.is_banned = False
        db.session.commit()
        
        message = f"User {user.username} has been unbanned!"
        
        if is_ajax_request():
            return jsonify({'success': True, 'message': message})
        
        flash(message, "success")
        return redirect(url_for('admin.admin_dashboard'))
    except Exception as e:
        logger.error(f"Error unbanning user {user_id}: {str(e)}")
        if is_ajax_request():
            return jsonify({'success': False, 'message': f'Error unbanning user: {str(e)}'}), 500
        flash(f'Error unbanning user: {str(e)}', 'danger')
        return redirect(url_for('admin.admin_dashboard'))

@admin_bp.route('/user/<int:user_id>/ban', methods=['POST'])
@login_required
@admin_required
def admin_ban_user(user_id):
    try:
        user = User.query.get_or_404(user_id)
        user.is_banned = True
        db.session.commit()
        
        message = f"User {user.username} has been banned!"
        
        if is_ajax_request():
            return jsonify({'success': True, 'message': message})
        
        flash(message, "success")
        return redirect(url_for('admin.admin_dashboard'))
    except Exception as e:
        logger.error(f"Error banning user {user_id}: {str(e)}")
        if is_ajax_request():
            return jsonify({'success': False, 'message': f'Error banning user: {str(e)}'}), 500
        flash(f'Error banning user: {str(e)}', 'danger')
        return redirect(url_for('admin.admin_dashboard'))

@admin_bp.route('/user/<int:user_id>/promote', methods=['POST'])
@login_required
@admin_required
def admin_promote_user(user_id):
    try:
        user = User.query.get_or_404(user_id)
        user.is_admin = True
        db.session.commit()
        
        message = f"User {user.username} has been promoted to admin!"
        
        if is_ajax_request():
            return jsonify({'success': True, 'message': message})
        
        flash(message, "success")
        return redirect(url_for('admin.admin_dashboard'))
    except Exception as e:
        logger.error(f"Error promoting user {user_id}: {str(e)}")
        if is_ajax_request():
            return jsonify({'success': False, 'message': f'Error promoting user: {str(e)}'}), 500
        flash(f'Error promoting user: {str(e)}', 'danger')
        return redirect(url_for('admin.admin_dashboard'))

@admin_bp.route('/user/<int:user_id>/demote', methods=['POST'])
@login_required
@admin_required
def admin_demote_user(user_id):
    try:
        user = User.query.get_or_404(user_id)
        # Prevent demoting yourself
        if user.id == current_user.id:
            message = "You cannot demote yourself!"
            if is_ajax_request():
                return jsonify({'success': False, 'message': message}), 400
            flash(message, "warning")
            return redirect(url_for('admin.admin_dashboard'))
        elif user.username == "Felix":
            message = "You cannot demote Main Admin!"
            if is_ajax_request():
                return jsonify({'success': False, 'message': message}), 400
            flash(message, "warning")
            return redirect(url_for('admin.admin_dashboard'))

        user.is_admin = False
        db.session.commit()
        
        message = f"User {user.username} has been demoted from admin!"
        
        if is_ajax_request():
            return jsonify({'success': True, 'message': message})
        
        flash(message, "success")
        return redirect(url_for('admin.admin_dashboard'))
    except Exception as e:
        logger.error(f"Error demoting user {user_id}: {str(e)}")
        if is_ajax_request():
            return jsonify({'success': False, 'message': f'Error demoting user: {str(e)}'}), 500
        flash(f'Error demoting user: {str(e)}', 'danger')
        return redirect(url_for('admin.admin_dashboard'))

# ---------------------- Post Management ----------------------
@admin_bp.route("/new_post", methods=["GET", "POST"])
@login_required
@admin_required
@check_ban
def new_post():
    if current_user.is_banned:
        if is_ajax_request():
            return jsonify({'success': False, 'message': 'You are banned and cannot create posts.'}), 403
        flash("You are banned and cannot create posts.", "danger")
        return redirect(url_for("main.index"))

    form = PostForm()

    try:
        categories = Category.query.order_by(Category.name).all()
        form.category.choices = [(c.id, c.name) for c in categories]
    except Exception as e:
        logger.error(f"Error loading categories: {str(e)}")
        # Fallback to empty choices
        form.category.choices = []
        flash("Error loading categories from database", "warning")
    
    # Dynamically populate category choices
    categories = Category.query.order_by(Category.name).all()
    form.category.choices = [(c.id, c.name) for c in categories]

    if form.validate_on_submit():
        try:
            title = form.title.data.strip()
            desc = form.desc.data.strip()
            
            # Sanitize description with bleach
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
            sanitized_desc = bleach.clean(desc, tags=allowed_tags, attributes=allowed_attributes, strip=True)

            # Handle file upload
            file = form.image.data
            filename = None
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
            else:
                if is_ajax_request():
                    return jsonify({'success': False, 'message': 'Invalid image format or no image selected.'}), 400
                flash("Invalid image format or no image selected.", "warning")
                return redirect(request.url)

            # Get selected category object
            selected_category = Category.query.get(form.category.data)

            # Create post
            post = Post(
                title=title,
                desc=sanitized_desc,
                category_obj=selected_category,
                image_url=filename,
                author=current_user
            )
            db.session.add(post)
            db.session.commit()

            if is_ajax_request():
                return jsonify({'success': True, 'message': 'Post created successfully!'})
            
            flash("Post created successfully!", "success")
            return redirect(url_for("admin.admin_dashboard"))

        except Exception as e:
            db.session.rollback()
            error_msg = f"Error creating post: {str(e)}"
            if is_ajax_request():
                return jsonify({'success': False, 'message': error_msg}), 500
            flash(error_msg, "danger")
            current_app.logger.error(f"Post creation error: {str(e)}")

    return render_template("new_post.html", form=form)

@admin_bp.route('/post/<int:post_id>/delete', methods=['POST'])
@login_required
def admin_delete_post(post_id):
    try:
        if not current_user.is_admin:
            if is_ajax_request():
                return jsonify({'success': False, 'message': 'Access Denied!'}), 403
            flash("Access Denied!", "danger")
            return redirect(url_for('main.index'))

        post = Post.query.get_or_404(post_id)
        db.session.delete(post)
        db.session.commit()
        
        message = "Post deleted successfully!"
        
        if is_ajax_request():
            return jsonify({'success': True, 'message': message})
        
        flash(message, "success")
        return redirect(url_for('admin.admin_dashboard'))
    except Exception as e:
        logger.error(f"Error deleting post {post_id}: {str(e)}")
        if is_ajax_request():
            return jsonify({'success': False, 'message': f'Error deleting post: {str(e)}'}), 500
        flash(f'Error deleting post: {str(e)}', 'danger')
        return redirect(url_for('admin.admin_dashboard'))

@admin_bp.route('/post/<int:post_id>/block', methods=['POST'])
@login_required
@admin_required
def admin_block_post(post_id):
    try:
        post = Post.query.get_or_404(post_id)
        post.is_blocked = True
        db.session.commit()
        
        message = "Post blocked successfully!"
        
        if is_ajax_request():
            return jsonify({'success': True, 'message': message})
        
        flash(message, "success")
        return redirect(url_for('admin.admin_dashboard'))
    except Exception as e:
        logger.error(f"Error blocking post {post_id}: {str(e)}")
        if is_ajax_request():
            return jsonify({'success': False, 'message': f'Error blocking post: {str(e)}'}), 500
        flash(f'Error blocking post: {str(e)}', 'danger')
        return redirect(url_for('admin.admin_dashboard'))

@admin_bp.route('/post/<int:post_id>/unblock', methods=['POST'])
@login_required
@admin_required
def admin_unblock_post(post_id):
    try:
        post = Post.query.get_or_404(post_id)
        post.is_blocked = False
        db.session.commit()
        
        message = "Post unblocked successfully!"
        
        if is_ajax_request():
            return jsonify({'success': True, 'message': message})
        
        flash(message, "success")
        return redirect(url_for('admin.admin_dashboard'))
    except Exception as e:
        logger.error(f"Error unblocking post {post_id}: {str(e)}")
        if is_ajax_request():
            return jsonify({'success': False, 'message': f'Error unblocking post: {str(e)}'}), 500
        flash(f'Error unblocking post: {str(e)}', 'danger')
        return redirect(url_for('admin.admin_dashboard'))

@admin_bp.route('/see_more/<int:post_id>')
def see_more(post_id):
    form = CommentForm()
    post = Post.query.get_or_404(post_id)
    recommended_posts = get_recommended_posts(post_id)
    if post.views is None:
        post.views = 0
    post.views += 1
    db.session.commit()
    comments = Comment.query.filter_by(post_id=post_id).all()
    return render_template('see_more.html', post=post, form=form, comments=comments, Like=Like, recommended_posts=recommended_posts)

@admin_bp.route('/edit_post/<int:post_id>', methods=['GET', 'POST'])
@login_required
@check_ban
def edit_post(post_id):
    if current_user.is_banned:
        if is_ajax_request():
            return jsonify({'success': False, 'message': 'You are banned and cannot edit posts.'}), 403
        flash("You are banned and cannot edit posts.", "danger")
        return redirect(url_for("main.index"))

    post = Post.query.get_or_404(post_id)
    if post.author != current_user and not current_user.is_admin:
        if is_ajax_request():
            return jsonify({'success': False, 'message': 'You do not have permission to edit this post.'}), 403
        flash("You do not have permission to edit this post.", "danger")
        return redirect(url_for('main.index'))

    form = PostForm(obj=post)
    
    categories = Category.query.order_by(Category.name).all()
    form.category.choices = [(c.id, c.name) for c in categories]
    
    if post.category_obj:
        form.category.data = post.category_obj.id

    if request.method == "POST" and form.validate_on_submit():
        try:
            post.title = form.data['title'].strip()
            desc = form.data['desc'].strip()

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
            post.desc = bleach.clean(desc, tags=allowed_tags, attributes=allowed_attributes, strip=True)

            # Update category 
            selected_category = Category.query.get(form.category.data)
            post.category_obj = selected_category

            file = request.files.get('image')
            if file and file.filename != "":
                if allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
                    file.save(file_path)
                    post.image_url = filename
                else:
                    if is_ajax_request():
                        return jsonify({'success': False, 'message': 'File type not allowed.'}), 400
                    flash('File type not allowed.', 'warning')
                    return redirect(request.url)

            db.session.commit()
            
            if is_ajax_request():
                return jsonify({'success': True, 'message': 'Post updated successfully'})
            
            flash("Post updated successfully", "success")
            return redirect(url_for("admin.see_more", post_id=post_id))
        except Exception as e:
            db.session.rollback()
            error_msg = f"Error updating post: {str(e)}"
            if is_ajax_request():
                return jsonify({'success': False, 'message': error_msg}), 500
            flash(error_msg, "danger")
            return redirect(url_for("admin.edit_post", post_id=post_id))

    return render_template("edit_post.html", form=form, post=post)

# ---------------------- Announcement Management ----------------------
@admin_bp.route('/announcement/create', methods=['GET', 'POST'])
@login_required
def create_announcement():
    if not current_user.is_admin:
        if is_ajax_request():
            return jsonify({'success': False, 'message': 'Access Denied!'}), 403
        flash("Access Denied!", "danger")
        return redirect(url_for('main.index'))

    form = AnnouncementForm()
    if form.validate_on_submit():
        try:
            announcement = Announcement(
                title=form.title.data,
                content=form.message.data,
                author_id=current_user.id
            )
            db.session.add(announcement)
            db.session.commit()
            
            if is_ajax_request():
                return jsonify({'success': True, 'message': 'Announcement created!'})
            
            flash("Announcement created!", "success")
            return redirect(url_for('admin.admin_dashboard'))
        except Exception as e:
            db.session.rollback()
            error_msg = f"Error creating announcement: {str(e)}"
            if is_ajax_request():
                return jsonify({'success': False, 'message': error_msg}), 500
            flash(error_msg, "danger")
            return redirect(url_for('admin.create_announcement'))

    return render_template('create_announcement.html', form=form)

@csrf.exempt
@admin_bp.route('/announcement/delete/<int:announcement_id>', methods=['POST'])
@login_required
def delete_announcement(announcement_id):
    if not current_user.is_admin:
        if is_ajax_request():
            return jsonify({'success': False, 'message': 'Access Denied!'}), 403
        flash("Access Denied!", "danger")
        return redirect(url_for('main.index'))  

    announcement = Announcement.query.get_or_404(announcement_id)
    try:
        db.session.delete(announcement)
        db.session.commit()
        
        message = "Announcement deleted successfully!"
        
        if is_ajax_request():
            return jsonify({'success': True, 'message': message})
        
        flash(message, "success")
    except Exception as e:
        error_message = f"An error occurred while deleting the announcement: {str(e)}"
        
        if is_ajax_request():
            return jsonify({'success': False, 'message': error_message}), 500
        
        flash(error_message, "danger")

    return redirect(url_for('admin.admin_dashboard'))

# ---------------------- Traffic Stats ----------------------
@admin_bp.route('/traffic')
@login_required
def admin_traffic_stats():
    if not current_user.is_admin:
        if is_ajax_request():
            return jsonify({'success': False, 'message': 'Access Denied!'}), 403
        flash("Access Denied!", "danger")
        return redirect(url_for('main.index'))

    from datetime import timedelta
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=30)
    traffic_stats = TrafficStats.query.filter(
        TrafficStats.timestamp.between(start_date, end_date)
    ).order_by(TrafficStats.timestamp.desc()).all()

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

# ---------------------- Video Management ----------------------
@admin_bp.route("/upload_video", methods=["GET", "POST"])
@login_required
@check_ban
def upload_video():
    if current_user.is_banned:
        if is_ajax_request():
            return jsonify({'success': False, 'message': 'You are banned and cannot upload videos.'}), 403
        flash("You are banned and cannot upload videos.", "danger")
        return redirect(url_for("main.index"))

    form = VideoForm()
    if request.method == "POST" and form.validate_on_submit():
        try:
            title = form.data['title'].strip()
            description = form.data['description'].strip()

            file = request.files.get('video')
            if not file or file.filename == "":
                if is_ajax_request():
                    return jsonify({'success': False, 'message': 'No video file selected.'}), 400
                flash("No video file selected.", "warning")
                return redirect(request.url)

            if allowed_file(file.filename, extensions=['mp4', 'mkv', 'avi', 'mov']):
                filename = secure_filename(file.filename)
                file_path = os.path.join(current_app.config['VIDEO_UPLOAD_FOLDER'], filename)
                file.save(file_path)

                video = Video(title=title, description=description, video_url=filename, author=current_user)
                db.session.add(video)
                db.session.commit()

                if is_ajax_request():
                    return jsonify({'success': True, 'message': 'Video uploaded successfully!'})
                
                flash("Video uploaded successfully!", "success")
                return redirect(url_for("index"))
            else:
                if is_ajax_request():
                    return jsonify({'success': False, 'message': 'Invalid video format. Allowed formats: mp4, mkv, avi, mov.'}), 400
                flash("Invalid video format. Allowed formats: mp4, mkv, avi, mov.", "danger")
                return redirect(request.url)
        except Exception as e:
            db.session.rollback()
            error_msg = f"Error uploading video: {str(e)}"
            if is_ajax_request():
                return jsonify({'success': False, 'message': error_msg}), 500
            flash(error_msg, "danger")
            return redirect(url_for('admin.upload_video'))

    return render_template("upload_video.html", form=form)

@admin_bp.route("/videos")
def videos():
    videos = Video.query.order_by(Video.upload_time.desc()).all()
    return render_template("videos.html", videos=videos)

@admin_bp.route('/search')
def search():
    query = request.args.get('q', '')
    if not query:
        if is_ajax_request():
            return jsonify({'success': False, 'message': 'Please enter a search term.'}), 400
        flash('Please enter a search term.', 'warning')
        return redirect(request.referrer or url_for('main.index'))
    
    # Get the current page from request args or default to page 1
    page = request.args.get('page', 1, type=int)
    per_page = 6
    
    # Split query into individual words
    search_terms = query.split()
    
    # Start with base query that filters out banned users and blocked posts
    base_query = Post.query.join(User).filter(
        User.is_banned == False, 
        Post.is_blocked == False
    )
    
    # Create a list of conditions for each search term
    conditions = []
    for term in search_terms:
        term_condition = (Post.title.ilike(f'%{term}%')) | (Post.desc.ilike(f'%{term}%'))
        conditions.append(term_condition)
    
    # Combine all conditions with OR to find posts matching any term
    if conditions:
        final_condition = conditions[0]
        for condition in conditions[1:]:
            final_condition = final_condition | condition
        
        # Apply the final condition to the base query
        results = base_query.filter(final_condition)
    else:
        # If no valid search terms, return all posts (shouldn't happen due to earlier check)
        results = base_query
    
    # Order by publication date and paginate
    results = results.order_by(Post.date_pub.desc()).paginate(page=page, per_page=per_page, error_out=False)
    
    # Pass the posts as 'posts' to match the template expectation
    return render_template('search_results.html', 
                         query=query, 
                         posts=results.items, 
                         pagination=results)

@admin_bp.route('/admin/ads_txt', methods=['GET', 'POST'])
@login_required
@admin_required
def manage_ads_txt():
    # Get the latest ads.txt entry or create a new one if none exists
    ads_txt = AdsTxt.query.order_by(AdsTxt.last_updated.desc()).first()

    form = AdsTxtForm()

    if ads_txt:
        form.content.data = ads_txt.content

    if form.validate_on_submit():
        try:
            # Create new entry (we keep history by creating new entries)
            new_ads_txt = AdsTxt(
                content=form.content.data.strip(),
                updated_by=current_user.id
            )
            db.session.add(new_ads_txt)
            db.session.commit()

            if is_ajax_request():
                return jsonify({'success': True, 'message': 'Ads.txt updated successfully!'})
            
            flash('Ads.txt updated successfully!', 'success')
            return redirect(url_for('admin.manage_ads_txt'))

        except Exception as e:
            db.session.rollback()
            error_msg = f'Error updating ads.txt: {str(e)}'
            if is_ajax_request():
                return jsonify({'success': False, 'message': error_msg}), 500
            flash(error_msg, 'danger')
            current_app.logger.error(f"Ads.txt update error: {str(e)}")

    return render_template('admin_ads_txt.html', form=form)

#---------------------manage subscribers-----------------------
@admin_bp.route('/admin/subscribers')
@login_required
@admin_required
def manage_subscribers():
    subscribers = NewsletterSubscriber.query.order_by(NewsletterSubscriber.subscribed_on.desc()).all()
    return render_template('admin_subscribers.html', subscribers=subscribers)

@admin_bp.route('/admin/subscriber/<int:subscriber_id>/unsubscribe', methods=['POST'])
@login_required
@admin_required
def unsubscribe_subscriber(subscriber_id):
    try:
        subscriber = NewsletterSubscriber.query.get_or_404(subscriber_id)
        subscriber.subscribed = False
        db.session.commit()
        
        message = f'{subscriber.email} has been unsubscribed successfully.'
        
        if is_ajax_request():
            return jsonify({'success': True, 'message': message})
        
        flash(message, 'success')
        return redirect(url_for('admin.manage_subscribers'))
    except Exception as e:
        logger.error(f"Error unsubscribing subscriber {subscriber_id}: {str(e)}")
        if is_ajax_request():
            return jsonify({'success': False, 'message': f'Error unsubscribing: {str(e)}'}), 500
        flash(f'Error unsubscribing: {str(e)}', 'danger')
        return redirect(url_for('admin.manage_subscribers'))

@admin_bp.route('/admin/subscriber/<int:subscriber_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_subscriber(subscriber_id):
    try:
        subscriber = NewsletterSubscriber.query.get_or_404(subscriber_id)
        db.session.delete(subscriber)
        db.session.commit()
        
        message = f'{subscriber.email} has been deleted completely.'
        
        if is_ajax_request():
            return jsonify({'success': True, 'message': message})
        
        flash(message, 'success')
        return redirect(url_for('admin.manage_subscribers'))
    except Exception as e:
        logger.error(f"Error deleting subscriber {subscriber_id}: {str(e)}")
        if is_ajax_request():
            return jsonify({'success': False, 'message': f'Error deleting: {str(e)}'}), 500
        flash(f'Error deleting: {str(e)}', 'danger')
        return redirect(url_for('admin.manage_subscribers'))

@admin_bp.route('/admin/subscriber/<int:subscriber_id>/resubscribe', methods=['POST'])
@login_required
@admin_required
def resubscribe_subscriber(subscriber_id):
    try:
        subscriber = NewsletterSubscriber.query.get_or_404(subscriber_id)
        subscriber.subscribed = True
        db.session.commit()
        
        message = f'{subscriber.email} has been resubscribed successfully.'
        
        if is_ajax_request():
            return jsonify({'success': True, 'message': message})
        
        flash(message, 'success')
        return redirect(url_for('admin.manage_subscribers'))
    except Exception as e:
        logger.error(f"Error resubscribing subscriber {subscriber_id}: {str(e)}")
        if is_ajax_request():
            return jsonify({'success': False, 'message': f'Error resubscribing: {str(e)}'}), 500
        flash(f'Error resubscribing: {str(e)}', 'danger')
        return redirect(url_for('admin.manage_subscribers'))

@admin_bp.route('/admin/newsletter', methods=['GET', 'POST'])
@login_required
@admin_required
def send_newsletter():
    form = NewsletterForm()

    # Calculate subscriber count in the view function
    subscribers_count = NewsletterSubscriber.query.filter_by(subscribed=True).count()

    if form.validate_on_submit():
        try:
            subject = form.subject.data.strip()
            message = form.message.data.strip()

            # Get all active subscribers
            subscribers = NewsletterSubscriber.query.filter_by(subscribed=True).all()

            if not subscribers:
                if is_ajax_request():
                    return jsonify({'success': False, 'message': 'No active subscribers to send newsletter to.'}), 400
                flash("No active subscribers to send newsletter to.", "warning")
                return redirect(url_for('admin.send_newsletter'))

            # Send email to each subscriber
            for subscriber in subscribers:
                msg = Message(
                    subject=subject,
                    recipients=[subscriber.email],
                    sender=current_app.config['MAIL_DEFAULT_SENDER']
                )

                # Create email body with unsubscribe link
                unsubscribe_url = url_for('main.unsubscribe_newsletter', email=subscriber.email, _external=True)
                email_body = f"""
{message}

---
To unsubscribe from our newsletter, click here: {unsubscribe_url}
"""
                msg.body = email_body

                try:
                    mail.send(msg)
                except Exception as e:
                    current_app.logger.error(f"Failed to send newsletter to {subscriber.email}: {str(e)}")
                    continue

            if is_ajax_request():
                return jsonify({'success': True, 'message': f'Newsletter sent successfully to {len(subscribers)} subscribers!'})
            
            flash(f"Newsletter sent successfully to {len(subscribers)} subscribers!", "success")
            return redirect(url_for('admin.admin_dashboard'))

        except Exception as e:
            db.session.rollback()
            error_msg = f"Error sending newsletter: {str(e)}"
            if is_ajax_request():
                return jsonify({'success': False, 'message': error_msg}), 500
            flash(error_msg, "danger")
            current_app.logger.error(f"Newsletter sending error: {str(e)}")

    # Pass the subscriber count to the template
    return render_template('admin_newsletter.html', form=form, subscribers_count=subscribers_count)

@admin_bp.route('/admin/ddos/stats')
@ddos_protection.middleware
def ddos_stats():
    stats = ddos_protection.get_stats()
    return jsonify(stats)

@admin_bp.route('/admin/ddos/ban/<ip>', methods=['POST'])
@login_required
@admin_required
def ban_ip(ip):
    try:
        ban_time = int(request.form.get('ban_time', 300))  
        ddos_protection.ban_ip(ip, ban_time)
        
        message = f'IP {ip} has been banned for {ban_time} seconds!'
        
        if is_ajax_request():
            return jsonify({'success': True, 'message': message})
        
        flash(message, 'success')
        return redirect(url_for('admin.ddos_protection'))
    except Exception as e:
        logger.error(f"Error banning IP {ip}: {str(e)}")
        if is_ajax_request():
            return jsonify({'success': False, 'message': f'Error banning IP: {str(e)}'}), 500
        flash(f'Error banning IP: {str(e)}', 'danger')
        return redirect(url_for('admin.ddos_protection'))

@admin_bp.route('/admin/ddos/unban/<ip>', methods=['POST'])
@login_required
@admin_required
def ddos_unban_ip(ip):
    try:
        ddos_protection.unban_ip(ip)
        
        message = f'IP {ip} has been unbanned successfully!'
        
        if is_ajax_request():
            return jsonify({'success': True, 'message': message})
        
        flash(message, 'success')
        return redirect(url_for('admin.ddos_protection_management'))
    except Exception as e:
        logger.error(f"Error unbanning IP {ip}: {str(e)}")
        if is_ajax_request():
            return jsonify({'success': False, 'message': f'Error unbanning IP: {str(e)}'}), 500
        flash(f'Error unbanning IP: {str(e)}', 'danger')
        return redirect(url_for('admin.ddos_protection_management'))

@admin_bp.route('/ddos-protection', methods=['GET', 'POST'])
@login_required
@admin_required
def ddos_protection_management():
    if request.method == 'POST':
        # Update DDoS protection configuration
        try:
            ddos_protection.config['MODE'] = request.form.get('protection_mode', 'active')
            ddos_protection.config['REQUEST_LIMIT'] = int(request.form.get('request_limit', 100))
            ddos_protection.config['WINDOW_SIZE'] = int(request.form.get('window_size', 60))
            ddos_protection.config['BAN_TIME'] = int(request.form.get('ban_time', 300))
            ddos_protection.config['AUTO_BAN'] = request.form.get('auto_ban') == 'true'

            if is_ajax_request():
                return jsonify({'success': True, 'message': 'DDoS protection settings updated successfully!'})
            
            flash('DDoS protection settings updated successfully!', 'success')
        except Exception as e:
            error_msg = f'Error updating settings: {str(e)}'
            if is_ajax_request():
                return jsonify({'success': False, 'message': error_msg}), 500
            flash(error_msg, 'danger')

    # Get current stats and configuration
    stats = ddos_protection.get_stats()
    banned_ips = {}

    # Get banned IPs information
    if ddos_protection.use_redis and ddos_protection.redis_client:
        try:
            # Get all banned IP keys from Redis
            banned_keys = ddos_protection.redis_client.keys('ban:*')
            for key in banned_keys:
                ip = key.decode().replace('ban:', '')
                ttl = ddos_protection.redis_client.ttl(key)
                banned_ips[ip] = {
                    'banned_until': datetime.utcnow().timestamp() + ttl if ttl > 0 else 0,
                    'reason': 'Rate limit exceeded'
                }
        except Exception as e:
            logger.error(f"Error getting banned IPs from Redis: {e}")
    else:
        # Get from in-memory storage
        for ip, ban_until in ddos_protection.banned_ips.items():
            banned_ips[ip] = {
                'banned_until': ban_until,
                'reason': 'Rate limit exceeded'
            }

    # Format banned until timestamps
    for ip_info in banned_ips.values():
        if ip_info['banned_until']:
            ip_info['banned_until'] = datetime.fromtimestamp(ip_info['banned_until']).strftime('%Y-%m-%d %H:%M:%S')

    return render_template('ddos_protection.html',
                         stats=stats,
                         config=ddos_protection.config,
                         banned_ips=banned_ips,
                         protection_mode=ddos_protection.config['MODE'])

@admin_bp.route('/manage-categories')
@admin_required
def manage_categories():
    categories = Category.query.all()
    
    # Calculate stats
    active_categories_count = Category.query.join(Post).group_by(Category.id).count()
    empty_categories_count = len(categories) - active_categories_count
    parent_categories_count = Category.query.filter_by(parent_id=None).count()
    
    # Create form instance
    form = CategoryForm()
    
    return render_template('manage_categories.html', 
                         categories=categories,
                         active_categories_count=active_categories_count,
                         empty_categories_count=empty_categories_count,
                         parent_categories_count=parent_categories_count,
                         form=form)

@admin_bp.route('/categories/add', methods=['POST'])
@admin_required
def add_category():
    form = CategoryForm()
    
    if form.validate_on_submit():
        try:
            # Handle parent_id (0 means no parent)
            parent_id = form.parent_id.data if form.parent_id.data != 0 else None
            
            category = Category(
                name=form.name.data.strip(),
                parent_id=parent_id
            )
            db.session.add(category)
            db.session.commit()
            
            if is_ajax_request():
                return jsonify({'success': True, 'message': 'Category added successfully!'})
            
            flash('Category added successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            error_msg = f'Error adding category: {str(e)}'
            if is_ajax_request():
                return jsonify({'success': False, 'message': error_msg}), 500
            flash(error_msg, 'danger')
            current_app.logger.error(f"Category addition error: {str(e)}")
    else:
        # Display form errors
        error_msgs = []
        for field, errors in form.errors.items():
            for error in errors:
                error_msgs.append(f'{field}: {error}')
        
        error_message = '; '.join(error_msgs)
        
        if is_ajax_request():
            return jsonify({'success': False, 'message': error_message}), 400
        
        for msg in error_msgs:
            flash(msg, 'danger')
    
    return redirect(url_for('admin.manage_categories'))

@admin_bp.route('/categories/<int:category_id>/edit', methods=['POST'])
@admin_required
def edit_category(category_id):
    category = Category.query.get_or_404(category_id)
    form = CategoryForm()
    
    if form.validate_on_submit():
        try:
            # Handle parent_id (0 means no parent)
            parent_id = form.parent_id.data if form.parent_id.data != 0 else None
            
            category.name = form.name.data.strip()
            category.parent_id = parent_id
            db.session.commit()
            
            if is_ajax_request():
                return jsonify({'success': True, 'message': 'Category updated successfully!'})
            
            flash('Category updated successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            error_msg = f'Error updating category: {str(e)}'
            if is_ajax_request():
                return jsonify({'success': False, 'message': error_msg}), 500
            flash(error_msg, 'danger')
            current_app.logger.error(f"Category update error: {str(e)}")
    else:
        # Display form errors
        error_msgs = []
        for field, errors in form.errors.items():
            for error in errors:
                error_msgs.append(f'{field}: {error}')
        
        error_message = '; '.join(error_msgs)
        
        if is_ajax_request():
            return jsonify({'success': False, 'message': error_message}), 400
        
        for msg in error_msgs:
            flash(msg, 'danger')
    
    return redirect(url_for('admin.manage_categories'))

@admin_bp.route('/categories/<int:category_id>/delete', methods=['POST'])
@admin_required
def delete_category(category_id):
    category = Category.query.get_or_404(category_id)
    
    # Check if category has posts or subcategories
    if category.posts.count() > 0 or category.children.count() > 0:
        message = 'Cannot delete category with posts or subcategories.'
        
        if is_ajax_request():
            return jsonify({'success': False, 'message': message}), 400
        
        flash(message, 'danger')
        return redirect(url_for('admin.manage_categories'))
    
    try:
        db.session.delete(category)
        db.session.commit()
        
        message = 'Category deleted successfully!'
        
        if is_ajax_request():
            return jsonify({'success': True, 'message': message})
        
        flash(message, 'success')
    except Exception as e:
        error_message = f'Error deleting category: {str(e)}'
        
        if is_ajax_request():
            return jsonify({'success': False, 'message': error_message}), 500
        
        flash(error_message, 'danger')
    
    return redirect(url_for('admin.manage_categories'))

@admin_bp.route('/api/docs')
@login_required
@admin_required
def api_docs():
    return render_template('api_docs.html')

# API Management Routes
@admin_bp.route('/api/keys')
@login_required
@admin_required
def manage_api_keys():
    api_keys = ApiKey.query.all()
    users = User.query.all()
    return render_template('admin_api_keys.html', api_keys=api_keys, users=users)

# API Key Management Routes
@admin_bp.route('/api/key/generate', methods=['POST'])
@login_required
@admin_required
def generate_api_key():
    user_id = request.form.get('user_id')
    permissions = request.form.get('permissions', 'post:create')

    user = User.query.get(user_id)
    if not user:
        if is_ajax_request():
            return jsonify({'success': False, 'message': 'User not found'}), 404
        flash('User not found', 'danger')
        return redirect(url_for('admin.manage_api_keys'))

    # Generate a secure API key
    api_key = secrets.token_urlsafe(32)

    # Create the API key record
    key_record = ApiKey(
        key=api_key,
        user_id=user_id,
        permissions=permissions
    )

    db.session.add(key_record)
    db.session.commit()

    # For AJAX requests, return the API key in the response
    if is_ajax_request():
        return jsonify({
            'success': True, 
            'message': f'API key generated for {user.username}',
            'api_key': api_key,
            'user': user.username
        })
    
    # For regular form submissions, flash the API key
    key_data = json.dumps({
        'api_key': api_key,
        'user': user.username
    })
    flash(key_data, 'api_key')
    flash(f'API key generated for {user.username}', 'success')
    
    return redirect(url_for('admin.manage_api_keys'))

@admin_bp.route('/api/key/<int:key_id>/deactivate', methods=['POST'])
@login_required
@admin_required
def deactivate_api_key(key_id):
    try:
        api_key = ApiKey.query.get_or_404(key_id)
        api_key.is_active = False
        db.session.commit()
        
        message = 'API key deactivated'
        
        if is_ajax_request():
            return jsonify({'success': True, 'message': message})
        
        flash(message, 'success')
        return redirect(url_for('admin.manage_api_keys'))
    except Exception as e:
        logger.error(f"Error deactivating API key {key_id}: {str(e)}")
        if is_ajax_request():
            return jsonify({'success': False, 'message': f'Error deactivating API key: {str(e)}'}), 500
        flash(f'Error deactivating API key: {str(e)}', 'danger')
        return redirect(url_for('admin.manage_api_keys'))

@admin_bp.route('/api/key/<int:key_id>/activate', methods=['POST'])
@login_required
@admin_required
def activate_api_key(key_id):
    try:
        api_key = ApiKey.query.get_or_404(key_id)
        api_key.is_active = True
        db.session.commit()
        
        message = 'API key activated'
        
        if is_ajax_request():
            return jsonify({'success': True, 'message': message})
        
        flash(message, 'success')
        return redirect(url_for('admin.manage_api_keys'))
    except Exception as e:
        logger.error(f"Error activating API key {key_id}: {str(e)}")
        if is_ajax_request():
            return jsonify({'success': False, 'message': f'Error activating API key: {str(e)}'}), 500
        flash(f'Error activating API key: {str(e)}', 'danger')
        return redirect(url_for('admin.manage_api_keys'))

@admin_bp.route('/api/key/<int:key_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_api_key(key_id):
    try:
        api_key = ApiKey.query.get_or_404(key_id)
        db.session.delete(api_key)
        db.session.commit()
        
        message = 'API key deleted'
        
        if is_ajax_request():
            return jsonify({'success': True, 'message': message})
        
        flash(message, 'success')
        return redirect(url_for('admin.manage_api_keys'))
    except Exception as e:
        logger.error(f"Error deleting API key {key_id}: {str(e)}")
        if is_ajax_request():
            return jsonify({'success': False, 'message': f'Error deleting API key: {str(e)}'}), 500
        flash(f'Error deleting API key: {str(e)}', 'danger')
        return redirect(url_for('admin.manage_api_keys'))

@admin_bp.route('/api/categories/internal')
def get_categories_internal():
    """Internal endpoint for getting categories without API limits"""
    try:
        categories = Category.query.order_by(Category.name).all()
        categories_data = [{'id': cat.id, 'name': cat.name} for cat in categories]
        return jsonify({'categories': categories_data})
    except Exception as e:
        logger.error(f"Error in internal categories endpoint: {str(e)}")
        return jsonify({'error': 'Failed to load categories'}), 500
