from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from app.models import User, Post,Comment, TrafficStats
from app.forms import AdminActionForm
from app import db
from flask_mail import Message
from app import mail
from datetime import datetime

admin_bp = Blueprint('admin', __name__)


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
@admin_bp.route('/admin/post/<int:post_id>/delete')
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
