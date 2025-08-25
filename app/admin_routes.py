import os
import bleach
import logging
from functools import wraps
from datetime import datetime
from werkzeug.utils import secure_filename
from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app
from flask_login import login_required, current_user
from flask_mail import Message

from app import db, mail,csrf
from app.models import User, Post, Comment, TrafficStats, Announcement, NewsletterSubscriber, Like, Video,Category,AdsTxt,NewsletterSubscriber
from app.forms import (
    AdminActionForm, VideoForm, LoginForm, RegisterForm, PostForm, CommentForm,
    ContactForm, ResetPasswordRequestForm, ResetPasswordForm, AnnouncementForm,AdsTxtForm,NewsletterForm
)

admin_bp = Blueprint('admin', __name__)
logger = logging.getLogger(__name__)


# Utility functions
def allowed_file(filename, extensions=None):
    if not extensions:
        extensions = ['jpg', 'jpeg', 'png', 'gif']
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in extensions


def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            flash("You need to log in to access this page.", "warning")
            return redirect(url_for("login"))
        if not current_user.is_admin:
            flash("You do not have the required permissions to access this page.", "danger")
            return redirect(url_for("main.index"))
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


def send_warning_email(user_email, message_body):
    msg = Message("Warning from Admin", recipients=[user_email])
    msg.body = message_body
    mail.send(msg)


# ---------------------- Admin Dashboard ----------------------
@admin_bp.route('/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash("Access Denied!", "danger")
        return redirect(url_for('main.index'))

    users = User.query.all()
    posts = Post.query.all()
    active_subscribers_count = NewsletterSubscriber.query.filter_by(subscribed=True).count()
    total_subscribers_count = NewsletterSubscriber.query.count()
    return render_template('admin_dashboard.html', users=users, posts=posts,active_subscribers_count=active_subscribers_count,total_subscribers_count=total_subscribers_count)  


# ---------------------- User Management ----------------------
@admin_bp.route('/user/<int:user_id>/action', methods=['GET', 'POST'])
@login_required
def admin_user_action(user_id):
    if not current_user.is_admin:
        flash("Access Denied!", "danger")
        return redirect(url_for('main.index'))

    user = User.query.get_or_404(user_id)
    form = AdminActionForm()

    if form.validate_on_submit():
        if form.is_banned.data:
            user.is_banned = True
            flash(f"User {user.username} has been banned!", "success")
        if form.warning_message.data:
            user.warning_message = form.warning_message.data
            msg = Message("Warning from Admin", recipients=[user.email])
            msg.body = f"Warning: {form.warning_message.data}"
            mail.send(msg)
            flash(f"Warning sent to {user.username}!", "success")

        db.session.commit()
        return redirect(url_for('admin.admin_dashboard'))

    return render_template('admin_user_action.html', user=user, form=form)


@admin_bp.route('/user/<int:user_id>/unban', methods=['GET', 'POST'])
@login_required
def admin_unban_user(user_id):
    if not current_user.is_admin:
        flash("Access Denied!", "danger")
        return redirect(url_for('main.index'))

    user = User.query.get_or_404(user_id)
    user.is_banned = False
    db.session.commit()
    flash(f"User {user.username} has been unbanned!", "success")
    return redirect(url_for('admin.admin_dashboard'))


# ---------------------- Post Management ----------------------
@admin_bp.route("/new_post", methods=["GET", "POST"])
@login_required
@admin_required
@check_ban
def new_post():
    if current_user.is_banned:
        flash("You are banned and cannot create posts.", "danger")
        return redirect(url_for("main.index"))

    form = PostForm()
    
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
                flash("Invalid image format or no image selected.", "warning")
                return redirect(request.url)

            # Get selected category object
            selected_category = Category.query.get(form.category.data)

            # Create post
            post = Post(
                title=title,
                desc=sanitized_desc,
                category_obj=selected_category,  # assign relationship
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
            current_app.logger.error(f"Post creation error: {str(e)}")

    return render_template("new_post.html", form=form)


@admin_bp.route('/post/<int:post_id>/delete', methods=['POST'])
@login_required
def admin_delete_post(post_id):
    if not current_user.is_admin:
        flash("Access Denied!", "danger")
        return redirect(url_for('main.index'))

    post = Post.query.get_or_404(post_id)
    db.session.delete(post)
    db.session.commit()
    flash("Post deleted successfully!", "success")
    return redirect(url_for('admin.admin_dashboard'))


@admin_bp.route('/post/<int:post_id>/block')
@login_required
def admin_block_post(post_id):
    if not current_user.is_admin:
        flash("Access Denied!", "danger")
        return redirect(url_for('main.index'))

    post = Post.query.get_or_404(post_id)
    post.is_blocked = True
    db.session.commit()
    flash("Post blocked successfully!", "success")
    return redirect(url_for('admin.admin_dashboard'))


@admin_bp.route('/post/<int:post_id>/unblock', methods=['GET', 'POST'])
@login_required
def admin_unblock_post(post_id):
    if not current_user.is_admin:
        flash("Access Denied!", "danger")
        return redirect(url_for('main.index'))

    post = Post.query.get_or_404(post_id)
    post.is_blocked = False
    db.session.commit()
    flash("Post unblocked successfully!", "success")
    return redirect(url_for('admin.admin_dashboard'))


@admin_bp.route('/see_more/<int:post_id>')
def see_more(post_id):
    form = CommentForm()
    post = Post.query.get_or_404(post_id)
    if post.views is None:
        post.views = 0
    post.views += 1
    db.session.commit()
    comments = Comment.query.filter_by(post_id=post_id).all()
    return render_template('see_more.html', post=post, form=form, comments=comments, Like=Like)


@admin_bp.route('/edit_post/<int:post_id>', methods=['GET', 'POST'])
@login_required
@check_ban
def edit_post(post_id):
    if current_user.is_banned:
        flash("You are banned and cannot edit posts.", "danger")
        return redirect(url_for("main.index"))

    post = Post.query.get_or_404(post_id)
    if post.author != current_user and not current_user.is_admin:
        flash("You do not have permission to edit this post.", "danger")
        return redirect(url_for('main.index'))

    form = PostForm(obj=post)
    
    
    categories = Category.query.order_by(Category.name).all()
    form.category.choices = [(c.id, c.name) for c in categories]
    
    
    if post.category_obj:
        form.category.data = post.category_obj.id

    if request.method == "POST" and form.validate_on_submit():
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
                flash('File type not allowed.', 'warning')
                return redirect(request.url)

        db.session.commit()
        flash("Post updated successfully", "success")
        return redirect(url_for("admin.see_more", post_id=post_id))  # Changed to redirect to the post

    return render_template("edit_post.html", form=form, post=post)


# ---------------------- Announcement Management ----------------------
@admin_bp.route('/announcement/create', methods=['GET', 'POST'])
@login_required
def create_announcement():
    if not current_user.is_admin:
        flash("Access Denied!", "danger")
        return redirect(url_for('main.index'))

    form = AnnouncementForm()
    if form.validate_on_submit():
        announcement = Announcement(
            title=form.title.data,
            content=form.message.data,
            author_id=current_user.id
        )
        db.session.add(announcement)
        db.session.commit()
        flash("Announcement created!", "success")
        return redirect(url_for('admin.admin_dashboard'))

    return render_template('create_announcement.html', form=form)

@csrf.exempt
@admin_bp.route('/announcement/delete/<int:announcement_id>', methods=['POST'])
@login_required
def delete_announcement(announcement_id):
    if not current_user.is_admin:
        flash("Access Denied!", "danger")
        return redirect(url_for('main.index'))  

    announcement = Announcement.query.get_or_404(announcement_id)
    try:
        db.session.delete(announcement)
        db.session.commit()
        flash("Announcement deleted successfully!", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"An error occurred while deleting the announcement: {str(e)}", "danger")

    return redirect(url_for('admin.admin_dashboard'))


# ---------------------- Traffic Stats ----------------------
@admin_bp.route('/traffic')
@login_required
def admin_traffic_stats():
    if not current_user.is_admin:
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
        flash("You are banned and cannot upload videos.", "danger")
        return redirect(url_for("main.index"))

    form = VideoForm()
    if request.method == "POST" and form.validate_on_submit():
        title = form.data['title'].strip()
        description = form.data['description'].strip()

        file = request.files.get('video')
        if not file or file.filename == "":
            flash("No video file selected.", "warning")
            return redirect(request.url)

        if allowed_file(file.filename, extensions=['mp4', 'mkv', 'avi', 'mov']):
            filename = secure_filename(file.filename)
            file_path = os.path.join(current_app.config['VIDEO_UPLOAD_FOLDER'], filename)
            file.save(file_path)

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
    videos = Video.query.order_by(Video.upload_time.desc()).all()
    return render_template("videos.html", videos=videos)



@admin_bp.route('/search')
def search():
    query = request.args.get('q', '')
    results = Post.query.filter(Post.title.contains(query) | Post.desc.contains(query)).all()
    return render_template('search_results.html', query=query, results=results)

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

            flash('Ads.txt updated successfully!', 'success')
            return redirect(url_for('admin.manage_ads_txt'))

        except Exception as e:
            db.session.rollback()
            flash(f'Error updating ads.txt: {str(e)}', 'danger')
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
    subscriber = NewsletterSubscriber.query.get_or_404(subscriber_id)
    subscriber.subscribed = False
    db.session.commit()
    flash(f'{subscriber.email} has been unsubscribed successfully.', 'success')
    return redirect(url_for('admin.manage_subscribers'))

@admin_bp.route('/admin/subscriber/<int:subscriber_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_subscriber(subscriber_id):
    subscriber = NewsletterSubscriber.query.get_or_404(subscriber_id)
    db.session.delete(subscriber)
    db.session.commit()
    flash(f'{subscriber.email} has been deleted completely.', 'success')
    return redirect(url_for('admin.manage_subscribers'))

@admin_bp.route('/admin/subscriber/<int:subscriber_id>/resubscribe', methods=['POST'])
@login_required
@admin_required
def resubscribe_subscriber(subscriber_id):
    subscriber = NewsletterSubscriber.query.get_or_404(subscriber_id)
    subscriber.subscribed = True
    db.session.commit()
    flash(f'{subscriber.email} has been resubscribed successfully.', 'success')
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

            flash(f"Newsletter sent successfully to {len(subscribers)} subscribers!", "success")
            return redirect(url_for('admin.admin_dashboard'))

        except Exception as e:
            db.session.rollback()
            flash(f"Error sending newsletter: {str(e)}", "danger")
            current_app.logger.error(f"Newsletter sending error: {str(e)}")

    # Pass the subscriber count to the template
    return render_template('admin_newsletter.html', form=form, subscribers_count=subscribers_count)
