from flask import Blueprint, render_template, redirect, url_for, flash, request
from app import db, mail
from app.models import NewsletterSubscriber, Announcement, Post
from flask_mail import Message
from flask_login import login_required, current_user
from app.forms import SubscribeForm

newsletter_bp = Blueprint('newsletter', __name__)
admin_bp = Blueprint('admin', __name__)

# Newsletter Subscription
@newsletter_bp.route('/subscribe', methods=['GET', 'POST'])
def subscribe():
    form = SubscribeForm()
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    if request.method == 'POST':
        email = request.form.get('email')
        if not email:
            flash("Please provide a valid email address.", "warning")
            return redirect(url_for('newsletter.subscribe'))

        # Check if email is already subscribed
        if NewsletterSubscriber.query.filter_by(email=email).first():
            flash("You are already subscribed to the newsletter.", "info")
            return redirect(url_for('newsletter.subscribe'))

        # Save subscription
        new_subscriber = NewsletterSubscriber(email=email)
        db.session.add(new_subscriber)
        db.session.commit()

        # Send a welcome email
        msg = Message("Welcome to our Newsletter!", recipients=[email])
        msg.body = "Thank you for subscribing to our newsletter. Stay tuned for updates!"
        mail.send(msg)

        flash("Subscription successful! Check your email for confirmation.", "success")
        return redirect(url_for('index'))

    return render_template('subscribe.html',form=form)


# Unsubscribe from Newsletter
@newsletter_bp.route('/unsubscribe/<int:subscriber_id>', methods=['GET', 'POST'])
def unsubscribe(subscriber_id):
    subscriber = NewsletterSubscriber.query.get_or_404(subscriber_id)

    db.session.delete(subscriber)  
    db.session.commit()

    flash(f"{subscriber.email} has been unsubscribed from all newsletters.", "success")
    return redirect(url_for('index'))


# Bulk Emailing
@newsletter_bp.route('/send_bulk_email', methods=['POST'])
@login_required
def send_bulk_email():
    if not current_user.is_admin:
        flash("Access Denied!", "danger")
        return redirect(url_for('main.index'))

    subject = request.form.get('subject')
    message_body = request.form.get('message_body')
    subscribers = NewsletterSubscriber.query.filter_by(subscribed=True).all()

    if not subscribers:
        flash("No active subscribers to send emails to.", "info")
        return redirect(url_for('admin.admin_dashboard'))

    for subscriber in subscribers:
        unsubscribe_link = url_for('newsletter.unsubscribe', subscriber_id=subscriber.id, _external=True)
        msg = Message(subject, recipients=[subscriber.email])
        msg.body = f"{message_body}\n\nTo unsubscribe, click here: {unsubscribe_link}"
        mail.send(msg)

    flash("Bulk emails sent successfully!", "success")
    return redirect(url_for('admin.admin_dashboard'))


# Notify Subscribers of New Posts
@admin_bp.route('/admin/post/create', methods=['GET', 'POST'])
@login_required
def create_post():
    if not current_user.is_admin:
        flash("Access Denied!", "danger")
        return redirect(url_for('main.index'))

    form = PostForm()

    if form.validate_on_submit():
        post = Post(
            title=form.title.data,
            desc=form.desc.data,
            image_url=form.image_url.data,
            author_id=current_user.id
        )
        db.session.add(post)
        db.session.commit()

        # Notify subscribers
        subscribers = NewsletterSubscriber.query.filter_by(subscribed=True).all()
        for subscriber in subscribers:
            unsubscribe_link = url_for('newsletter.unsubscribe', subscriber_id=subscriber.id, _external=True)
            msg = Message(f"New Post Published: {post.title}", recipients=[subscriber.email])
            msg.body = f"Check out our latest post: {post.title}\n\n{post.desc}\n\nTo unsubscribe, click here: {unsubscribe_link}"
            mail.send(msg)

        flash("Post created and subscribers notified!", "success")
        return redirect(url_for('admin.admin_dashboard'))

    return render_template('create_post.html', form=form)




