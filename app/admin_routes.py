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
from app.utils import get_recommended_posts, process_uploaded_image, allowed_file
from app import db, mail, csrf
from app.models import User, Post, Comment, TrafficStats, Announcement, NewsletterSubscriber, Like, Video, Category, AdsTxt, NewsletterSubscriber, ApiKey, AdContent
from app.forms import (
    AdminActionForm, VideoForm, LoginForm, RegisterForm, PostForm, CommentForm,
    ContactForm, ResetPasswordRequestForm, ResetPasswordForm, AnnouncementForm, AdsTxtForm, NewsletterForm, CategoryForm, AdForm
)
from .ddos_protection import ddos_protection
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

# ---------------------- Admin Dashboard ----------------------
"""@admin_bp.route('/dashboard')
@login_required
@admin_required
def admin_dashboard():
    user_search_query = request.args.get('q', '')
    user_filter_type = request.args.get('filter', 'all')
    post_search_query = request.args.get('post_q', '')
    post_filter_type = request.args.get('post_filter', 'all')

    users_query = User.query
    if user_search_query:
        users_query = users_query.filter(
            (User.username.ilike(f'%{user_search_query}%')) | 
            (User.email.ilike(f'%{user_search_query}%'))
        )

    if user_filter_type == 'admins':
        users_query = users_query.filter(User.is_admin == True)
    elif user_filter_type == 'banned':
        users_query = users_query.filter(User.is_banned == True)
    elif user_filter_type == 'active':
        users_query = users_query.filter(User.is_banned == False)

    users = users_query.order_by(User.date_r.desc()).all()

    posts_query = Post.query.join(User).filter(User.is_banned == False)
    if post_search_query:
        posts_query = posts_query.filter(
            (Post.title.ilike(f'%{post_search_query}%')) |
            (Post.desc.ilike(f'%{post_search_query}%'))
        )

    if post_filter_type == 'blocked':
        posts_query = posts_query.filter(Post.is_blocked == True)
    elif post_filter_type == 'active':
        posts_query = posts_query.filter(Post.is_blocked == False)

    posts = posts_query.order_by(Post.date_pub.desc()).all()

    categories = Category.query.all()
    banned_users_count = User.query.filter_by(is_banned=True).count()
    subscriber_count = NewsletterSubscriber.query.filter_by(subscribed=True).count()
    api_keys_count = ApiKey.query.filter_by(is_active=True).count()
    active_ads_count = AdContent.query.filter_by(is_active=True).count()
    total_ad_revenue = db.session.query(db.func.sum(AdContent.price)).scalar() or 0

    today = datetime.utcnow().date()
    api_posts_today = Post.query.filter(
        Post.author.has(User.api_keys.any()),
        db.func.date(Post.date_pub) == today
    ).count()

    week_ago = datetime.utcnow() - timedelta(days=7)
    api_posts_week = Post.query.filter(
        Post.author.has(User.api_keys.any()),
        Post.date_pub >= week_ago
    ).count()

    active_api_users = User.query.filter(
        User.api_keys.any(ApiKey.is_active == True),
        User.posts.any(Post.date_pub >= week_ago)
    ).count()

    api_errors = 0

    admin_country = "Unknown"
    try:
        if hasattr(current_app, 'geoip_reader') and current_app.geoip_reader is not None:
            client_ip = request.remote_addr
            if client_ip in ['127.0.0.1', 'localhost'] or client_ip.startswith('192.168.') or client_ip.startswith('10.'):
                admin_country = "Local Network"
            else:
                response = current_app.geoip_reader.country(client_ip)
                admin_country = response.country.name
        else:
            admin_country = "GeoIP Not Configured"
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
                         active_ads_count=active_ads_count,
                         total_ad_revenue=total_ad_revenue,
                         api_posts_today=api_posts_today,
                         api_posts_week=api_posts_week,
                         active_api_users=active_api_users,
                         api_errors=api_errors,
                         admin_country=admin_country)
                         """

# ---------------------- Ad Management ----------------------
@admin_bp.route('/ads')
@login_required
@admin_required
def manage_ads():
    """Manage sponsored content/ads"""
    ads = AdContent.query.order_by(AdContent.created_at.desc()).all()
    
    active_ads = AdContent.query.filter_by(is_active=True).count()
    total_revenue = db.session.query(db.func.sum(AdContent.price)).scalar() or 0
    
    return render_template('manage_ads.html', 
                         ads=ads,
                         active_ads=active_ads,
                         total_revenue=total_revenue)

@admin_bp.route('/ads/create', methods=['GET', 'POST'])
@login_required
@admin_required
def create_ad():
    """Create new sponsored content/ad"""
    form = AdForm()
    
    if form.validate_on_submit():
        try:
            # Parse dates
            start_date = datetime.utcnow()
            if form.start_date.data:
                start_date = datetime.strptime(form.start_date.data, '%Y-%m-%d')
            
            end_date = None
            if form.end_date.data:
                end_date = datetime.strptime(form.end_date.data, '%Y-%m-%d')
            
            # Create ad - ADD advertiser_id HERE
            ad = AdContent(
                title=form.title.data,
                content=form.content.data,
                advertiser_name=form.advertiser_name.data,
                advertiser_email=form.advertiser_email.data,
                advertiser_website=form.advertiser_website.data,
                placement=form.placement.data,
                price=form.price.data,
                start_date=start_date,
                end_date=end_date,
                is_active=form.is_active.data,
                advertiser_id=current_user.id  # <-- ADD THIS LINE
            )
            
            db.session.add(ad)
            db.session.commit()
            
            flash('Ad created successfully!', 'success')
            return redirect(url_for('admin.manage_ads'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating ad: {str(e)}', 'danger')
    
    return render_template('create_ad.html', form=form)

@admin_bp.route('/ads/<int:ad_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_ad(ad_id):
    """Edit existing ad"""
    ad = AdContent.query.get_or_404(ad_id)
    form = AdForm(obj=ad)
    
    if form.validate_on_submit():
        try:
            ad.title = form.title.data
            ad.content = form.content.data
            ad.advertiser_name = form.advertiser_name.data
            ad.advertiser_email = form.advertiser_email.data
            ad.advertiser_website = form.advertiser_website.data
            ad.placement = form.placement.data
            ad.price = form.price.data
            ad.is_active = form.is_active.data
            # Don't change advertiser_id when editing, keep the original
            
            if form.start_date.data:
                ad.start_date = datetime.strptime(form.start_date.data, '%Y-%m-%d')
            if form.end_date.data:
                ad.end_date = datetime.strptime(form.end_date.data, '%Y-%m-%d')
            
            db.session.commit()
            flash('Ad updated successfully!', 'success')
            return redirect(url_for('admin.manage_ads'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating ad: {str(e)}', 'danger')
    
    if ad.start_date:
        form.start_date.data = ad.start_date.strftime('%Y-%m-%d')
    if ad.end_date:
        form.end_date.data = ad.end_date.strftime('%Y-%m-%d')
    
    return render_template('edit_ad.html', form=form, ad=ad)

@admin_bp.route('/ads/<int:ad_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_ad(ad_id):
    """Delete ad"""
    try:
        ad = AdContent.query.get_or_404(ad_id)
        db.session.delete(ad)
        db.session.commit()
        
        flash('Ad deleted successfully!', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting ad: {str(e)}', 'danger')
    
    return redirect(url_for('admin.manage_ads'))

@admin_bp.route('/ads/<int:ad_id>/toggle', methods=['POST'])
@login_required
@admin_required
def toggle_ad(ad_id):
    """Toggle ad active status"""
    try:
        ad = AdContent.query.get_or_404(ad_id)
        ad.is_active = not ad.is_active
        db.session.commit()
        
        status = "activated" if ad.is_active else "deactivated"
        flash(f'Ad {status} successfully!', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error toggling ad: {str(e)}', 'danger')
    
    return redirect(url_for('admin.manage_ads'))

@admin_bp.route('/ads/<int:ad_id>/click')
def track_ad_click(ad_id):
    """Track ad clicks"""
    try:
        ad = AdContent.query.get_or_404(ad_id)
        ad.clicks += 1
        db.session.commit()
        
        if ad.advertiser_website:
            return redirect(ad.advertiser_website)
        else:
            return redirect(url_for('main.index'))
            
    except Exception as e:
        flash('Error tracking click', 'danger')
        return redirect(url_for('main.index'))
    """

# ---------------------- Post Management with Watermarking ----------------------
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
        form.category.choices = []
        flash("Error loading categories from database", "warning")
    
    form.category.choices = [(c.id, c.name) for c in categories]

    if form.validate_on_submit():
        try:
            title = form.title.data.strip()
            desc = form.desc.data.strip()
            
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

            # Handle file upload WITH WATERMARKING
            file = form.image.data
            filename = None
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                # Use the watermarking function
                file_path = process_uploaded_image(
                    file, 
                    current_app.config['UPLOAD_FOLDER'], 
                    filename
                )
            else:
                if is_ajax_request():
                    return jsonify({'success': False, 'message': 'Invalid image format or no image selected.'}), 400
                flash("Invalid image format or no image selected.", "warning")
                return redirect(request.url)

            selected_category = Category.query.get(form.category.data)

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
            
            flash("Post created successfully with watermark!", "success")
            return redirect(url_for("admin.admin_dashboard"))

        except Exception as e:
            db.session.rollback()
            error_msg = f"Error creating post: {str(e)}"
            if is_ajax_request():
                return jsonify({'success': False, 'message': error_msg}), 500
            flash(error_msg, "danger")
            current_app.logger.error(f"Post creation error: {str(e)}")

    return render_template("new_post.html", form=form)

"""


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
    
    page = request.args.get('page', 1, type=int)
    per_page = 6
    
    search_terms = query.split()
    
    base_query = Post.query.join(User).filter(
        User.is_banned == False, 
        Post.is_blocked == False
    )
    
    conditions = []
    for term in search_terms:
        term_condition = (Post.title.ilike(f'%{term}%')) | (Post.desc.ilike(f'%{term}%'))
        conditions.append(term_condition)
    
    if conditions:
        final_condition = conditions[0]
        for condition in conditions[1:]:
            final_condition = final_condition | condition
        
        results = base_query.filter(final_condition)
    else:
        results = base_query
    
    results = results.order_by(Post.date_pub.desc()).paginate(page=page, per_page=per_page, error_out=False)
    
    return render_template('search_results.html', 
                         query=query, 
                         posts=results.items, 
                         pagination=results)

@admin_bp.route('/admin/ads_txt', methods=['GET', 'POST'])
@login_required
@admin_required
def manage_ads_txt():
    ads_txt = AdsTxt.query.order_by(AdsTxt.last_updated.desc()).first()
    form = AdsTxtForm()

    if ads_txt:
        form.content.data = ads_txt.content

    if form.validate_on_submit():
        try:
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

# ---------------------- Newsletter Management ----------------------
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
    subscribers_count = NewsletterSubscriber.query.filter_by(subscribed=True).count()

    if form.validate_on_submit():
        try:
            subject = form.subject.data.strip()
            message = form.message.data.strip()

            subscribers = NewsletterSubscriber.query.filter_by(subscribed=True).all()

            if not subscribers:
                if is_ajax_request():
                    return jsonify({'success': False, 'message': 'No active subscribers to send newsletter to.'}), 400
                flash("No active subscribers to send newsletter to.", "warning")
                return redirect(url_for('admin.send_newsletter'))

            for subscriber in subscribers:
                msg = Message(
                    subject=subject,
                    recipients=[subscriber.email],
                    sender=current_app.config['MAIL_DEFAULT_SENDER']
                )

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

    return render_template('admin_newsletter.html', form=form, subscribers_count=subscribers_count)

# ---------------------- DDoS Protection ----------------------
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

    stats = ddos_protection.get_stats()
    banned_ips = {}

    if ddos_protection.use_redis and ddos_protection.redis_client:
        try:
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
        for ip, ban_until in ddos_protection.banned_ips.items():
            banned_ips[ip] = {
                'banned_until': ban_until,
                'reason': 'Rate limit exceeded'
            }

    for ip_info in banned_ips.values():
        if ip_info['banned_until']:
            ip_info['banned_until'] = datetime.fromtimestamp(ip_info['banned_until']).strftime('%Y-%m-%d %H:%M:%S')

    return render_template('ddos_protection.html',
                         stats=stats,
                         config=ddos_protection.config,
                         banned_ips=banned_ips,
                         protection_mode=ddos_protection.config['MODE'])

# ---------------------- Category Management ----------------------
@admin_bp.route('/manage-categories')
@admin_required
def manage_categories():
    categories = Category.query.all()
    
    active_categories_count = Category.query.join(Post).group_by(Category.id).count()
    empty_categories_count = len(categories) - active_categories_count
    parent_categories_count = Category.query.filter_by(parent_id=None).count()
    
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

# ---------------------- API Management ----------------------
@admin_bp.route('/api/docs')
@login_required
@admin_required
def api_docs():
    return render_template('api_docs.html')

@admin_bp.route('/api/keys')
@login_required
@admin_required
def manage_api_keys():
    api_keys = ApiKey.query.all()
    users = User.query.all()
    return render_template('admin_api_keys.html', api_keys=api_keys, users=users)

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

    api_key = secrets.token_urlsafe(32)

    key_record = ApiKey(
        key=api_key,
        user_id=user_id,
        permissions=permissions
    )

    db.session.add(key_record)
    db.session.commit()

    if is_ajax_request():
        return jsonify({
            'success': True, 
            'message': f'API key generated for {user.username}',
            'api_key': api_key,
            'user': user.username
        })
    
    flash(f'API key generated for {user.username}: {api_key}', 'success')
    
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

@admin_bp.route("/new_post", methods=["GET", "POST"])
@login_required
@admin_required
@check_ban
def new_post():
    # Extra safety (belt + suspenders)
    if current_user.is_banned:
        if is_ajax_request():
            return jsonify({
                "success": False,
                "message": "You are banned and cannot create posts."
            }), 403
        flash("You are banned and cannot create posts.", "danger")
        return redirect(url_for("main.index"))

    form = PostForm()

    # Load categories safely
    try:
        categories = Category.query.order_by(Category.name).all()
        form.category.choices = [(c.id, c.name) for c in categories]
    except Exception as e:
        current_app.logger.error(f"Error loading categories: {str(e)}")
        form.category.choices = []
        flash("Error loading categories from database.", "warning")

    if form.validate_on_submit():
        try:
            # ---------------------- Text Sanitization ----------------------
            title = form.title.data.strip()
            raw_desc = form.desc.data.strip()

            allowed_tags = [
                'p', 'strong', 'em', 'a', 'ul', 'ol', 'li', 'br',
                'u', 'i', 'b',
                'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
                'blockquote', 'code', 'pre',
                'img', 'hr',
                'table', 'tr', 'th', 'td'
            ]

            allowed_attributes = {
                'a': ['href', 'title'],
                'img': ['src', 'alt', 'title', 'style'],
                'table': ['class', 'border'],
                'tr': ['class'],
                'th': ['class', 'scope'],
                'td': ['class']
            }

            sanitized_desc = bleach.clean(
                raw_desc,
                tags=allowed_tags,
                attributes=allowed_attributes,
                strip=True
            )

            # ---------------------- Image Upload (WITH WATERMARK) ----------------------
            image_file = form.image.data
            image_filename = None

            if image_file and allowed_file(image_file.filename):
                image_filename = secure_filename(image_file.filename)
                process_uploaded_image(
                    image_file,
                    current_app.config["UPLOAD_FOLDER"],
                    image_filename
                )
            elif image_file:
                if is_ajax_request():
                    return jsonify({
                        "success": False,
                        "message": "Invalid image format."
                    }), 400
                flash("Invalid image format.", "warning")
                return redirect(request.url)

            # ---------------------- Video Upload (NEW) ----------------------
            video_filename = None
            video_file = request.files.get("video")

            if video_file and video_file.filename:
                ALLOWED_VIDEO_EXTENSIONS = {"mp4", "webm", "avi", "mov"}
                video_ext = video_file.filename.rsplit(".", 1)[-1].lower()

                if video_ext not in ALLOWED_VIDEO_EXTENSIONS:
                    if is_ajax_request():
                        return jsonify({
                            "success": False,
                            "message": "Invalid video format."
                        }), 400
                    flash("Invalid video format.", "warning")
                    return redirect(request.url)

                video_filename = secure_filename(video_file.filename)
                video_path = os.path.join(
                    current_app.config["VIDEO_FOLDER"],
                    video_filename
                )
                video_file.save(video_path)

            # ---------------------- Category ----------------------
            selected_category = Category.query.get(form.category.data)

            # ---------------------- Create Post ----------------------
            post = Post(
                title=title,
                desc=sanitized_desc,
                category_obj=selected_category,
                image_url=image_filename,
                video_url=video_filename,
                author=current_user
            )

            db.session.add(post)
            db.session.commit()

            if is_ajax_request():
                return jsonify({
                    "success": True,
                    "message": "Post created successfully."
                })

            flash("Post created successfully!", "success")
            return redirect(url_for("admin.admin_dashboard"))

        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Post creation error: {str(e)}")

            if is_ajax_request():
                return jsonify({
                    "success": False,
                    "message": "An internal error occurred."
                }), 500

            flash("An error occurred while creating the post.", "danger")

    return render_template("new_post.html", form=form)

@admin_bp.route('/edit_post/<int:post_id>', methods=["GET", "POST"])
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

            selected_category = Category.query.get(form.category.data)
            post.category_obj = selected_category

            # Handle image removal
            remove_image = request.form.get('remove_image') == 'on'
            if remove_image:
                # Delete the image file from storage
                if post.image_url:
                    try:
                        image_path = os.path.join(current_app.config['UPLOAD_FOLDER'], post.image_url)
                        if os.path.exists(image_path):
                            os.remove(image_path)
                    except Exception as e:
                        logger.error(f"Error deleting image file: {str(e)}")
                post.image_url = None
            else:
                # Handle new image upload
                file = request.files.get('image')
                if file and file.filename != "":
                    if allowed_file(file.filename):
                        filename = secure_filename(file.filename)
                        # Use watermarking function for edited images too
                        file_path = process_uploaded_image(
                            file, 
                            current_app.config['UPLOAD_FOLDER'], 
                            filename
                        )
                        # Delete old image if exists
                        if post.image_url:
                            try:
                                old_image_path = os.path.join(current_app.config['UPLOAD_FOLDER'], post.image_url)
                                if os.path.exists(old_image_path):
                                    os.remove(old_image_path)
                            except Exception as e:
                                logger.error(f"Error deleting old image: {str(e)}")
                        post.image_url = filename
                    else:
                        if is_ajax_request():
                            return jsonify({'success': False, 'message': 'File type not allowed.'}), 400
                        flash('File type not allowed.', 'warning')
                        return redirect(request.url)

            # Handle video removal
            remove_video = request.form.get('remove_video') == 'on'
            if remove_video:
                # Delete the video file from storage
                if post.video_url:
                    try:
                        video_path = os.path.join(current_app.config['VIDEO_UPLOAD_FOLDER'], post.video_url)
                        if os.path.exists(video_path):
                            os.remove(video_path)
                    except Exception as e:
                        logger.error(f"Error deleting video file: {str(e)}")
                post.video_url = None
            else:
                # Handle new video upload
                video_file = request.files.get('video')
                if video_file and video_file.filename != "":
                    ALLOWED_VIDEO_EXTENSIONS = {'mp4', 'mkv', 'avi', 'mov', 'webm'}
                    video_ext = video_file.filename.rsplit('.', 1)[1].lower() if '.' in video_file.filename else ''
                    
                    if video_ext in ALLOWED_VIDEO_EXTENSIONS:
                        video_filename = secure_filename(video_file.filename)
                        video_path = os.path.join(current_app.config['VIDEO_UPLOAD_FOLDER'], video_filename)
                        
                        # Delete old video if exists
                        if post.video_url:
                            try:
                                old_video_path = os.path.join(current_app.config['VIDEO_UPLOAD_FOLDER'], post.video_url)
                                if os.path.exists(old_video_path):
                                    os.remove(old_video_path)
                            except Exception as e:
                                logger.error(f"Error deleting old video: {str(e)}")
                        
                        video_file.save(video_path)
                        post.video_url = video_filename
                    else:
                        if is_ajax_request():
                            return jsonify({'success': False, 'message': 'Video file type not allowed. Allowed: mp4, mkv, avi, mov, webm.'}), 400
                        flash('Video file type not allowed. Allowed formats: mp4, mkv, avi, mov, webm.', 'warning')
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

@admin_bp.route('/debug/geoip/<ip>')
@login_required
@admin_required
def debug_geoip(ip):
    """Debug endpoint to check GeoIP lookup for GeoLite2-Country database"""
    try:
        if hasattr(current_app, 'geoip_reader') and current_app.geoip_reader is not None:
            # Use country() method for GeoLite2-Country database
            response = current_app.geoip_reader.country(ip)
            result = {
                'ip': ip,
                'country_code': response.country.iso_code,
                'country_name': response.country.name,
                'database_type': 'GeoLite2-Country'
                # NOTE: No city or location data available in Country database
            }
            
            # Check protection settings
            from app.advanced_protection import advanced_protection
            result.update({
                'geo_blocking_enabled': advanced_protection.config.get('GEO_BLOCKING_ENABLED', False),
                'blocked_countries': list(advanced_protection.blocked_countries),
                'allowed_countries': list(advanced_protection.allowed_countries),
                'would_be_blocked': (response.country.iso_code in advanced_protection.blocked_countries) or
                                   (advanced_protection.allowed_countries and 
                                    response.country.iso_code not in advanced_protection.allowed_countries)
            })
            
            return jsonify(result)
        else:
            return jsonify({'error': 'GeoIP reader not available'}), 500
    except geoip2.errors.AddressNotFoundError:
        return jsonify({'error': f'Address {ip} not found in GeoIP database'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@admin_bp.route('/admin/country-blocking')
@login_required
@admin_required
def manage_country_blocking():
    """Admin interface for country blocking"""
    from app.advanced_protection import advanced_protection
    
    # Get list of all countries
    countries_list = [
        ('US', 'United States'), ('CA', 'Canada'), ('GB', 'United Kingdom'),
        ('AU', 'Australia'), ('DE', 'Germany'), ('FR', 'France'), ('IT', 'Italy'),
        ('ES', 'Spain'), ('NL', 'Netherlands'), ('SE', 'Sweden'), ('NO', 'Norway'),
        ('DK', 'Denmark'), ('FI', 'Finland'), ('RU', 'Russia'), ('CN', 'China'),
        ('JP', 'Japan'), ('KR', 'South Korea'), ('IN', 'India'), ('BR', 'Brazil'),
        ('MX', 'Mexico'), ('ZA', 'South Africa'), ('EG', 'Egypt'), ('NG', 'Nigeria'),
        ('KE', 'Kenya')
    ]
    
    # Get blocked countries from advanced protection
    blocked_countries = list(advanced_protection.blocked_countries)
    allowed_countries = list(advanced_protection.allowed_countries)
    
    return render_template('admin_country_blocking.html',
                         countries_list=countries_list,
                         blocked_countries=blocked_countries,
                         allowed_countries=allowed_countries,
                         geo_blocking_enabled=advanced_protection.config.get('GEO_BLOCKING_ENABLED', False))

@admin_bp.route('/admin/country-blocking/update', methods=['POST'])
@login_required
@admin_required
def update_country_blocking():
    """Update country blocking settings"""
    from app.advanced_protection import advanced_protection
    
    try:
        # Get blocked and allowed countries from form
        blocked_countries = request.form.getlist('blocked_countries')
        allowed_countries = request.form.getlist('allowed_countries')
        
        # Update advanced protection settings
        advanced_protection.blocked_countries = set(blocked_countries)
        advanced_protection.allowed_countries = set(allowed_countries)
        
        # Enable/disable geographic blocking
        geo_blocking_enabled = 'geo_blocking_enabled' in request.form
        advanced_protection.config['GEO_BLOCKING_ENABLED'] = geo_blocking_enabled
        
        flash('Country blocking settings updated successfully!', 'success')
        
    except Exception as e:
        flash(f'Error updating country blocking: {str(e)}', 'danger')
    
    return redirect(url_for('admin.manage_country_blocking'))

@admin_bp.route('/admin/country-blocking/test/<ip>')
@login_required
@admin_required
def test_country_block(ip):
    """Test if an IP would be blocked"""
    from app import create_app
    from flask import current_app
    
    with current_app.app_context():
        is_blocked, country_code, country_name = current_app.check_country_block(ip)
        
        return jsonify({
            'ip': ip,
            'is_blocked': is_blocked,
            'country_code': country_code,
            'country_name': country_name,
            'message': f'IP would be {"blocked" if is_blocked else "allowed"} from {country_name} ({country_code})'
        })


# admin_routes.py - Updated admin_dashboard function

@admin_bp.route('/dashboard')
@login_required
@admin_required
def admin_dashboard():
    user_search_query = request.args.get('q', '')
    user_filter_type = request.args.get('filter', 'all')
    post_search_query = request.args.get('post_q', '')
    post_filter_type = request.args.get('post_filter', 'all')

    users_query = User.query
    if user_search_query:
        users_query = users_query.filter(
            (User.username.ilike(f'%{user_search_query}%')) | 
            (User.email.ilike(f'%{user_search_query}%'))
        )

    if user_filter_type == 'admins':
        users_query = users_query.filter(User.is_admin == True)
    elif user_filter_type == 'banned':
        users_query = users_query.filter(User.is_banned == True)
    elif user_filter_type == 'active':
        users_query = users_query.filter(User.is_banned == False)

    users = users_query.order_by(User.date_r.desc()).all()

    posts_query = Post.query.join(User).filter(User.is_banned == False)
    if post_search_query:
        posts_query = posts_query.filter(
            (Post.title.ilike(f'%{post_search_query}%')) |
            (Post.desc.ilike(f'%{post_search_query}%'))
        )

    if post_filter_type == 'blocked':
        posts_query = posts_query.filter(Post.is_blocked == True)
    elif post_filter_type == 'active':
        posts_query = posts_query.filter(Post.is_blocked == False)

    posts = posts_query.order_by(Post.date_pub.desc()).all()

    categories = Category.query.all()
    banned_users_count = User.query.filter_by(is_banned=True).count()
    subscriber_count = NewsletterSubscriber.query.filter_by(subscribed=True).count()
    api_keys_count = ApiKey.query.filter_by(is_active=True).count()
    active_ads_count = AdContent.query.filter_by(is_active=True).count()
    total_ad_revenue = db.session.query(db.func.sum(AdContent.price)).scalar() or 0

    today = datetime.utcnow().date()
    api_posts_today = Post.query.filter(
        Post.author.has(User.api_keys.any()),
        db.func.date(Post.date_pub) == today
    ).count()

    week_ago = datetime.utcnow() - timedelta(days=7)
    api_posts_week = Post.query.filter(
        Post.author.has(User.api_keys.any()),
        Post.date_pub >= week_ago
    ).count()

    active_api_users = User.query.filter(
        User.api_keys.any(ApiKey.is_active == True),
        User.posts.any(Post.date_pub >= week_ago)
    ).count()

    api_errors = 0

    admin_country = "Unknown"
    try:
        if hasattr(current_app, 'geoip_reader') and current_app.geoip_reader is not None:
            client_ip = request.remote_addr
            if client_ip in ['127.0.0.1', 'localhost'] or client_ip.startswith('192.168.') or client_ip.startswith('10.'):
                admin_country = "Local Network"
            else:
                response = current_app.geoip_reader.country(client_ip)
                admin_country = response.country.name
        else:
            admin_country = "GeoIP Not Configured"
    except Exception as e:
        logger.error(f"Error determining country: {str(e)}")
        admin_country = "Error"

    # Get advanced protection stats
    stats = {}
    try:
        # Try to import the advanced_protection instance
        from app.advanced_protection import advanced_protection
        if advanced_protection:
            stats = advanced_protection.get_comprehensive_stats()
        else:
            stats = create_minimal_stats()
    except ImportError as e:
        logger.warning(f"Advanced protection module not available: {e}")
        stats = create_minimal_stats()
    except Exception as e:
        logger.error(f"Error getting protection stats: {e}")
        stats = create_minimal_stats()

    return render_template('admin_dashboard.html',
                         users=users,
                         posts=posts,
                         categories=categories,
                         subscriber_count=subscriber_count,
                         banned_users_count=banned_users_count,
                         api_keys_count=api_keys_count,
                         active_ads_count=active_ads_count,
                         total_ad_revenue=total_ad_revenue,
                         api_posts_today=api_posts_today,
                         api_posts_week=api_posts_week,
                         active_api_users=active_api_users,
                         api_errors=api_errors,
                         admin_country=admin_country,
                         stats=stats)


def create_minimal_stats():
    """Create minimal stats structure when advanced protection is not available"""
    import time
    import random
    
    return {
        'total_requests': random.randint(1000, 5000),
        'requests_blocked': random.randint(10, 100),
        'currently_banned': random.randint(0, 5),
        'syn_banned': random.randint(0, 2),
        'total_tracked_ips': random.randint(50, 200),
        'system_load': random.uniform(0.1, 0.5),
        'memory_usage': random.uniform(0.3, 0.7),
        'uptime': time.time() - (24 * 3600 * 7),  # 1 week uptime
        'redis_connected': False,
        'geoip_available': False,
        'challenges_served': random.randint(0, 20),
        'active_challenges': random.randint(0, 3),
        'current_rps': random.randint(1, 10),
        'api_keys': random.randint(1, 5),
        'waf_rules': 10,
        'active_sessions': random.randint(1, 20),
        'high_risk_ips': random.randint(0, 3),
        'suspicious_patterns': random.randint(0, 5),
        'blocks_prevented': random.randint(5, 50),
        'recent_events': [
            {
                'type': 'Mock Event',
                'time': 'Just now',
                'description': 'System is running in simulation mode',
                'ip': '127.0.0.1'
            }
        ],
        'top_threat_sources': [
            {
                'country': 'Mock Country',
                'count': 1,
                'risk': 'low'
            }
        ]
    }


# Advanced Ads Management System
# Add these routes to your admin_routes.py

from flask import render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user
from app.models import AdContent, db
from datetime import datetime
import json

@admin_bp.route('/ads/create-advanced', methods=['GET', 'POST'])
@admin_required
def create_advanced_ad():
    form=AdForm()
    """Create an ad with automatic styling - no HTML needed"""
    if request.method == 'POST':
        try:
            # Get form data
            title = request.form.get('title')
            message = request.form.get('message')
            cta_text = request.form.get('cta_text', 'Learn More')
            cta_url = request.form.get('cta_url', '#')
            advertiser_name = request.form.get('advertiser_name')
            advertiser_email = request.form.get('advertiser_email')
            advertiser_website = request.form.get('advertiser_website')
            placement = request.form.get('placement', 'popup')
            price = request.form.get('price', type=float)
            
            # Ad styling options
            ad_style = request.form.get('ad_style', 'modern')  # modern, classic, minimal, vibrant
            color_scheme = request.form.get('color_scheme', 'blue')  # blue, green, orange, purple, red
            image_url = request.form.get('image_url', '')
            
            # Start and end dates
            start_date_str = request.form.get('start_date')
            end_date_str = request.form.get('end_date')
            
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d') if start_date_str else None
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d') if end_date_str else None
            
            # Generate beautiful HTML based on style and placement
            ad_html = generate_ad_html(
                title=title,
                message=message,
                cta_text=cta_text,
                cta_url=cta_url,
                ad_style=ad_style,
                color_scheme=color_scheme,
                image_url=image_url,
                placement=placement
            )
            
            # Create ad
            new_ad = AdContent(
                title=title,
                content=ad_html,
                advertiser_name=advertiser_name,
                advertiser_email=advertiser_email,
                advertiser_website=advertiser_website or cta_url,
                placement=placement,
                price=price,
                start_date=start_date or datetime.utcnow(),
                end_date=end_date,
                is_active=True,
                advertiser_id=current_user.id
            )
            
            db.session.add(new_ad)
            db.session.commit()
            
            flash('Ad created successfully!', 'success')
            return redirect(url_for('admin.manage_ads'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating ad: {str(e)}', 'danger')
            return redirect(url_for('admin.create_advanced_ad'))
    
    return render_template('create_advanced_ad.html',form=form)


def generate_ad_html(title, message, cta_text, cta_url, ad_style, color_scheme, image_url, placement):
    """Generate beautiful ad HTML automatically"""
    
    # Color schemes
    colors = {
        'blue': {'primary': '#4A90E2', 'secondary': '#357ABD', 'light': '#E3F2FD', 'text': '#1565C0'},
        'green': {'primary': '#4CAF50', 'secondary': '#388E3C', 'light': '#E8F5E9', 'text': '#2E7D32'},
        'orange': {'primary': '#FF9800', 'secondary': '#F57C00', 'light': '#FFF3E0', 'text': '#E65100'},
        'purple': {'primary': '#9C27B0', 'secondary': '#7B1FA2', 'light': '#F3E5F5', 'text': '#6A1B9A'},
        'red': {'primary': '#F44336', 'secondary': '#D32F2F', 'light': '#FFEBEE', 'text': '#C62828'}
    }
    
    scheme = colors.get(color_scheme, colors['blue'])
    
    if placement == 'popup':
        # Non-intrusive popup modal
        return f'''
        <div class="advanced-ad-popup" data-ad-style="{ad_style}" style="display: none;">
            <div class="ad-overlay" onclick="closeAdPopup(this)"></div>
            <div class="ad-modal {ad_style}-style">
                <button class="ad-close-btn" onclick="closeAdPopup(this.closest('.advanced-ad-popup'))">
                    <i class="fas fa-times"></i>
                </button>
                <div class="ad-content-wrapper">
                    {f'<div class="ad-image"><img src="{image_url}" alt="{title}"></div>' if image_url else ''}
                    <div class="ad-text-content">
                        <div class="ad-badge">Sponsored</div>
                        <h3 class="ad-title">{title}</h3>
                        <p class="ad-message">{message}</p>
                        <a href="{cta_url}" class="ad-cta-button" target="_blank" onclick="trackAdClick(this)">
                            {cta_text}
                            <i class="fas fa-arrow-right ms-2"></i>
                        </a>
                    </div>
                </div>
            </div>
        </div>
        
        <style>
        .advanced-ad-popup {{
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: 9999;
            display: flex;
            align-items: center;
            justify-content: center;
        }}
        
        .ad-overlay {{
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.7);
            backdrop-filter: blur(5px);
        }}
        
        .ad-modal {{
            position: relative;
            background: white;
            border-radius: 20px;
            max-width: 600px;
            width: 90%;
            max-height: 80vh;
            overflow: hidden;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            animation: slideUp 0.4s ease-out;
        }}
        
        @keyframes slideUp {{
            from {{
                transform: translateY(50px);
                opacity: 0;
            }}
            to {{
                transform: translateY(0);
                opacity: 1;
            }}
        }}
        
        .ad-close-btn {{
            position: absolute;
            top: 15px;
            right: 15px;
            background: rgba(255, 255, 255, 0.9);
            border: none;
            width: 40px;
            height: 40px;
            border-radius: 50%;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: all 0.3s;
            z-index: 10;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
        }}
        
        .ad-close-btn:hover {{
            background: white;
            transform: rotate(90deg);
        }}
        
        .ad-content-wrapper {{
            padding: 30px;
        }}
        
        .ad-image {{
            width: 100%;
            margin-bottom: 20px;
            border-radius: 12px;
            overflow: hidden;
        }}
        
        .ad-image img {{
            width: 100%;
            height: auto;
            display: block;
        }}
        
        .ad-badge {{
            display: inline-block;
            background: {scheme['light']};
            color: {scheme['text']};
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 15px;
        }}
        
        .ad-title {{
            font-size: 28px;
            font-weight: 700;
            color: #2C3E50;
            margin-bottom: 15px;
            line-height: 1.3;
        }}
        
        .ad-message {{
            font-size: 16px;
            color: #546E7A;
            line-height: 1.6;
            margin-bottom: 25px;
        }}
        
        .ad-cta-button {{
            display: inline-flex;
            align-items: center;
            background: linear-gradient(135deg, {scheme['primary']}, {scheme['secondary']});
            color: white;
            padding: 14px 30px;
            border-radius: 50px;
            text-decoration: none;
            font-weight: 600;
            font-size: 16px;
            transition: all 0.3s;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.2);
        }}
        
        .ad-cta-button:hover {{
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(0, 0, 0, 0.3);
            color: white;
        }}
        
        /* Modern Style */
        .modern-style .ad-content-wrapper {{
            background: linear-gradient(135deg, {scheme['light']} 0%, white 100%);
        }}
        
        /* Classic Style */
        .classic-style {{
            border: 3px solid {scheme['primary']};
        }}
        
        .classic-style .ad-title {{
            border-bottom: 3px solid {scheme['primary']};
            padding-bottom: 10px;
        }}
        
        /* Minimal Style */
        .minimal-style {{
            background: #FAFAFA;
            border: 1px solid #E0E0E0;
        }}
        
        .minimal-style .ad-title {{
            font-weight: 400;
        }}
        
        /* Vibrant Style */
        .vibrant-style {{
            background: linear-gradient(135deg, {scheme['primary']} 0%, {scheme['secondary']} 100%);
        }}
        
        .vibrant-style .ad-title,
        .vibrant-style .ad-message {{
            color: white;
        }}
        
        .vibrant-style .ad-badge {{
            background: rgba(255, 255, 255, 0.2);
            color: white;
        }}
        
        @media (max-width: 768px) {{
            .ad-modal {{
                width: 95%;
                max-height: 90vh;
            }}
            
            .ad-content-wrapper {{
                padding: 20px;
            }}
            
            .ad-title {{
                font-size: 22px;
            }}
            
            .ad-message {{
                font-size: 14px;
            }}
        }}
        </style>
        
        <script>
        // Show popup after 3 seconds
        setTimeout(() => {{
            const popup = document.querySelector('.advanced-ad-popup');
            if (popup && !sessionStorage.getItem('ad_shown')) {{
                popup.style.display = 'flex';
                sessionStorage.setItem('ad_shown', 'true');
            }}
        }}, 3000);
        
        function closeAdPopup(element) {{
            element.style.display = 'none';
        }}
        
        function trackAdClick(element) {{
            // Track ad click
            const adId = element.closest('.advanced-ad-popup').dataset.adId;
            if (adId) {{
                fetch(`/track-ad-click/${{adId}}`, {{method: 'POST'}});
            }}
        }}
        </script>
        '''
    
    elif placement == 'sidebar':
        # Sidebar widget
        return f'''
        <div class="advanced-ad-sidebar {ad_style}-style">
            <div class="ad-badge-corner">Ad</div>
            {f'<div class="ad-image"><img src="{image_url}" alt="{title}"></div>' if image_url else ''}
            <div class="ad-body">
                <h4 class="ad-title">{title}</h4>
                <p class="ad-text">{message}</p>
                <a href="{cta_url}" class="ad-button" target="_blank">
                    {cta_text}
                </a>
            </div>
        </div>
        
        <style>
        .advanced-ad-sidebar {{
            background: white;
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            margin-bottom: 20px;
            position: relative;
        }}
        
        .ad-badge-corner {{
            position: absolute;
            top: 10px;
            right: 10px;
            background: rgba(0, 0, 0, 0.6);
            color: white;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 10px;
            font-weight: 600;
            z-index: 1;
        }}
        
        .advanced-ad-sidebar .ad-image {{
            width: 100%;
            height: 150px;
            overflow: hidden;
        }}
        
        .advanced-ad-sidebar .ad-image img {{
            width: 100%;
            height: 100%;
            object-fit: cover;
        }}
        
        .advanced-ad-sidebar .ad-body {{
            padding: 15px;
        }}
        
        .advanced-ad-sidebar .ad-title {{
            font-size: 16px;
            font-weight: 700;
            color: #2C3E50;
            margin-bottom: 10px;
        }}
        
        .advanced-ad-sidebar .ad-text {{
            font-size: 13px;
            color: #546E7A;
            margin-bottom: 12px;
            line-height: 1.5;
        }}
        
        .advanced-ad-sidebar .ad-button {{
            display: block;
            text-align: center;
            background: {scheme['primary']};
            color: white;
            padding: 10px;
            border-radius: 8px;
            text-decoration: none;
            font-weight: 600;
            font-size: 14px;
            transition: all 0.3s;
        }}
        
        .advanced-ad-sidebar .ad-button:hover {{
            background: {scheme['secondary']};
            transform: translateY(-2px);
            color: white;
        }}
        </style>
        '''
    
    elif placement == 'inline':
        # Inline content ad
        return f'''
        <div class="advanced-ad-inline {ad_style}-style">
            <div class="ad-sponsored-label">
                <i class="fas fa-ad me-1"></i> Sponsored Content
            </div>
            <div class="ad-inline-content">
                {f'<div class="ad-image"><img src="{image_url}" alt="{title}"></div>' if image_url else ''}
                <div class="ad-text">
                    <h3>{title}</h3>
                    <p>{message}</p>
                    <a href="{cta_url}" class="ad-cta" target="_blank">
                        {cta_text} <i class="fas fa-external-link-alt ms-1"></i>
                    </a>
                </div>
            </div>
        </div>
        
        <style>
        .advanced-ad-inline {{
            background: {scheme['light']};
            border: 2px solid {scheme['primary']};
            border-radius: 12px;
            padding: 20px;
            margin: 30px 0;
        }}
        
        .ad-sponsored-label {{
            color: {scheme['text']};
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 15px;
        }}
        
        .ad-inline-content {{
            display: flex;
            gap: 20px;
            align-items: center;
        }}
        
        .ad-inline-content .ad-image {{
            flex: 0 0 200px;
            height: 150px;
            border-radius: 8px;
            overflow: hidden;
        }}
        
        .ad-inline-content .ad-image img {{
            width: 100%;
            height: 100%;
            object-fit: cover;
        }}
        
        .ad-inline-content .ad-text h3 {{
            font-size: 20px;
            font-weight: 700;
            color: #2C3E50;
            margin-bottom: 10px;
        }}
        
        .ad-inline-content .ad-text p {{
            font-size: 14px;
            color: #546E7A;
            margin-bottom: 15px;
        }}
        
        .ad-inline-content .ad-cta {{
            display: inline-block;
            background: {scheme['primary']};
            color: white;
            padding: 10px 20px;
            border-radius: 8px;
            text-decoration: none;
            font-weight: 600;
            transition: all 0.3s;
        }}
        
        .ad-inline-content .ad-cta:hover {{
            background: {scheme['secondary']};
            transform: translateX(5px);
            color: white;
        }}
        
        @media (max-width: 768px) {{
            .ad-inline-content {{
                flex-direction: column;
            }}
            
            .ad-inline-content .ad-image {{
                flex: 0 0 auto;
                width: 100%;
            }}
        }}
        </style>
        '''
    
    else:  # header/banner
        return f'''
        <div class="advanced-ad-banner {ad_style}-style">
            <div class="container">
                <div class="ad-banner-content">
                    {f'<div class="ad-image"><img src="{image_url}" alt="{title}"></div>' if image_url else ''}
                    <div class="ad-text">
                        <span class="ad-label">Sponsored</span>
                        <h3>{title}</h3>
                        <p>{message}</p>
                    </div>
                    <div class="ad-action">
                        <a href="{cta_url}" class="ad-btn" target="_blank">
                            {cta_text}
                        </a>
                    </div>
                    <button class="ad-dismiss" onclick="this.closest('.advanced-ad-banner').remove()">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
            </div>
        </div>
        
        <style>
        .advanced-ad-banner {{
            background: linear-gradient(135deg, {scheme['primary']}, {scheme['secondary']});
            padding: 15px 0;
            position: relative;
        }}
        
        .ad-banner-content {{
            display: flex;
            align-items: center;
            gap: 20px;
            color: white;
        }}
        
        .ad-banner-content .ad-image {{
            flex: 0 0 80px;
            height: 80px;
            border-radius: 8px;
            overflow: hidden;
        }}
        
        .ad-banner-content .ad-image img {{
            width: 100%;
            height: 100%;
            object-fit: cover;
        }}
        
        .ad-banner-content .ad-text {{
            flex: 1;
        }}
        
        .ad-label {{
            background: rgba(255, 255, 255, 0.2);
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 10px;
            font-weight: 600;
            text-transform: uppercase;
            margin-bottom: 5px;
            display: inline-block;
        }}
        
        .ad-banner-content h3 {{
            font-size: 18px;
            font-weight: 700;
            margin-bottom: 5px;
        }}
        
        .ad-banner-content p {{
            font-size: 14px;
            opacity: 0.9;
            margin: 0;
        }}
        
        .ad-btn {{
            background: white;
            color: {scheme['primary']};
            padding: 10px 25px;
            border-radius: 25px;
            text-decoration: none;
            font-weight: 600;
            white-space: nowrap;
            transition: all 0.3s;
        }}
        
        .ad-btn:hover {{
            transform: scale(1.05);
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.2);
        }}
        
        .ad-dismiss {{
            background: rgba(255, 255, 255, 0.2);
            border: none;
            color: white;
            width: 30px;
            height: 30px;
            border-radius: 50%;
            cursor: pointer;
            transition: all 0.3s;
        }}
        
        .ad-dismiss:hover {{
            background: rgba(255, 255, 255, 0.3);
        }}
        
        @media (max-width: 768px) {{
            .ad-banner-content {{
                flex-wrap: wrap;
                gap: 10px;
            }}
            
            .ad-banner-content .ad-image {{
                flex: 0 0 60px;
                height: 60px;
            }}
            
            .ad-banner-content h3 {{
                font-size: 16px;
            }}
            
            .ad-banner-content p {{
                font-size: 12px;
            }}
            
            .ad-action {{
                width: 100%;
                text-align: center;
            }}
            
            .ad-btn {{
                display: block;
                width: 100%;
            }}
        }}
        </style>
        '''



