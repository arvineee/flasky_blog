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
        return redirect(url_for('main.login'))
    
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

        # Send a professional HTML welcome email
        unsubscribe_link = url_for('newsletter.unsubscribe', subscriber_id=new_subscriber.id, _external=True)
        msg = Message(
            "Welcome to Arval Blog  Newsletter",
            recipients=[email]
        )
        msg.html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Welcome to [Your Website Name]</title>
    <style>
        body {{
            margin: 0;
            padding: 0;
            font-family: 'Helvetica', Arial, sans-serif;
            background-color: #f4f4f4;
            color: #333;
        }}
        .email-container {{
            max-width: 600px;
            margin: 0 auto;
            background-color: #ffffff;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }}
        .header {{
            background-color: #007bff;
            color: #ffffff;
            text-align: center;
            padding: 30px 20px;
        }}
        .header img {{
            max-width: 120px;
            margin-bottom: 10px;
        }}
        .content {{
            padding: 30px 20px;
            line-height: 1.6;
        }}
        .content h1 {{
            color: #2c3e50;
        }}
        .button {{
            display: inline-block;
            padding: 12px 25px;
            margin: 20px 0;
            background-color: #007bff;
            color: #ffffff;
            text-decoration: none;
            border-radius: 5px;
        }}
        .footer {{
            background-color: #f1f1f1;
            text-align: center;
            padding: 15px 20px;
            font-size: 12px;
            color: #888888;
        }}
        .footer a {{
            color: #007bff;
            text-decoration: none;
        }}
    </style>
</head>
<body>
    <div class="email-container">
        <div class="header">
    <img src="{{ url_for('static', filename='logo.png') }}" alt="Arval Blog Logo">
    <h2>Welcome to Arval Blog</h2>
        </div>
        <div class="content">
            <h1>Hello {email},</h1>
            <p>Thank you for subscribing to our newsletter! We're thrilled to have you as part of our community.</p>
            <p>You'll now receive regular updates, expert insights, and exclusive content straight to your inbox. We promise to deliver value with every email.</p>
            <p>Explore our website and stay updated with the latest content:</p>
            <a href="http://localhost:5000" class="button">Visit Our Website</a>
            <p>We're always here if you have questions or suggestions—just reply to this email!</p>
            <p>Best regards,<br>The Arval Blog Team</p>
        </div>
        <div class="footer">
            <p>If you did not subscribe, you can safely ignore this email or <a href="{unsubscribe_link}">unsubscribe here</a>.</p>
        </div>
    </div>
</body>
</html>
"""
        mail.send(msg)

        flash("Subscription successful! Check your email for confirmation.", "success")
        return redirect(url_for('main.index'))

    return render_template('subscribe.html', form=form)


# Unsubscribe from Newsletter
@newsletter_bp.route('/unsubscribe/<int:subscriber_id>', methods=['GET', 'POST'])
def unsubscribe(subscriber_id):
    subscriber = NewsletterSubscriber.query.get_or_404(subscriber_id)

    db.session.delete(subscriber)  
    db.session.commit()

    flash(f"{subscriber.email} has been unsubscribed from all newsletters.", "success")
    return redirect(url_for('main.index'))


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
        msg = Message(
            subject="Welcome to [Your Website Name] Newsletter",
            recipients=[subscriber.email]
        )
        msg.html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Welcome to [Your Website Name]</title>
    <style>
        body {{
            margin: 0;
            padding: 0;
            font-family: 'Helvetica', Arial, sans-serif;
            background-color: #f4f4f4;
            color: #333;
        }}
        .email-container {{
            max-width: 600px;
            margin: 0 auto;
            background-color: #ffffff;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }}
        .header {{
            background-color: #007bff;
            color: #ffffff;
            text-align: center;
            padding: 30px 20px;
        }}
        .header img {{
            max-width: 120px;
            margin-bottom: 10px;
        }}
        .content {{
            padding: 30px 20px;
            line-height: 1.6;
        }}
        .content h1 {{
            color: #2c3e50;
        }}
        .button {{
            display: inline-block;
            padding: 12px 25px;
            margin: 20px 0;
            background-color: #007bff;
            color: #ffffff;
            text-decoration: none;
            border-radius: 5px;
        }}
        .footer {{
            background-color: #f1f1f1;
            text-align: center;
            padding: 15px 20px;
            font-size: 12px;
            color: #888888;
        }}
        .footer a {{
            color: #007bff;
            text-decoration: none;
        }}
    </style>
</head>
<body>
    <div class="email-container">
        <div class="header">
            <img src="https://yourwebsite.com/logo.png" alt="[Your Website Name] Logo">
            <h2>Welcome to [Your Website Name]</h2>
        </div>
        <div class="content">
            <h1>Hello {subscriber.email},</h1>
            <p>Thank you for subscribing to our newsletter! We're thrilled to have you as part of our community.</p>
            <p>You'll now receive regular updates, expert insights, and exclusive content straight to your inbox. We promise to deliver value with every email.</p>
            <p>Explore our website and stay updated with the latest content:</p>
            <a href="https://yourwebsite.com" class="button">Visit Our Website</a>
            <p>We're always here if you have questions or suggestions—just reply to this email!</p>
            <p>Best regards,<br>The [Your Website Name] Team</p>
        </div>
        <div class="footer">
            <p>If you did not subscribe, you can safely ignore this email or <a href="{unsubscribe_link}">unsubscribe here</a>.</p>
        </div>
    </div>
</body>
</html>
"""
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

    from app.forms import PostForm  # Import here to avoid circular imports
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
