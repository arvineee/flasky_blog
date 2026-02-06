from flask import render_template, url_for, redirect, flash, request,send_file,jsonify,Blueprint,current_app,abort,make_response,current_app
from app import  bootstrap,db,login_manager,mail
from app.models import User, Post, Comment, Like, User,Announcement,Category,AdsTxt,NewsletterSubscriber,AdContent,Video
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
from datetime import datetime
from sqlalchemy import func, desc, and_ ,or_, case
import math

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

    # Get active sidebar ads
    ads = AdContent.query.filter(
        AdContent.is_active == True,
        AdContent.placement == 'sidebar',
        (AdContent.end_date == None) | (AdContent.end_date >= datetime.utcnow())
    ).order_by(AdContent.created_at.desc()).limit(2).all()

    # Update impressions for each ad
    for ad in ads:
        ad.impressions += 1
    db.session.commit()

    # Render the index page with posts and announcements
    return render_template('index.html', 
                         posts=posts,  # Now this is a list, not a pagination object
                         pagination=pagination,  # Pass the pagination object separately
                         featured_posts=featured_posts,
                         announcements=announcements,
                         recommended_posts=recommended_posts,
                         trending_categories=trending_categories,
                         active_tab=tab,
                         ads=ads,  # Pass ads to template
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

@main.route('/check_liked_posts', methods=['POST'])
@login_required
def check_liked_posts():
    """Check which posts the current user has liked"""
    try:
        data = request.get_json()
        post_ids = data.get('post_ids', [])
        
        # Query for likes by current user for these posts
        liked_posts = Like.query.filter(
            Like.user_id == current_user.id,
            Like.post_id.in_(post_ids)
        ).all()
        
        liked_post_ids = [like.post_id for like in liked_posts]
        
        return jsonify({
            'status': 'success',
            'liked_posts': liked_post_ids
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

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
                          sender=current_app.config['MAIL_USERNAME'],
                          recipients=[user.email])
            link = url_for('main.reset_password', token=token, _external=True)
            msg.body = f'Here is your password reset link: {link}'
            mail.send(msg)
            flash('An email with instructions to reset your password has been sent.', 'info')
        return redirect(url_for('main.login'))
    return render_template('reset_password_request.html', form=form)

@main.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
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

@main.route('/ad/click/<int:ad_id>')
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



'''
@main.route('/following')
@login_required
def following():
    #""Get posts from followed authors"
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    # Get IDs of authors the current user follows
    # For now, we'll show posts from users the current user has interacted with (liked/commented)
    
    # Get users whose posts the current user has liked
    liked_author_ids = db.session.query(Post.author_id).join(Like).filter(
        Like.user_id == current_user.id
    ).distinct().all()
    
    # Get users whose posts the current user has commented on
    commented_author_ids = db.session.query(Post.author_id).join(Comment).filter(
        Comment.user_id == current_user.id
    ).distinct().all()
    
    # Combine and get unique author IDs
    followed_ids = set([id[0] for id in liked_author_ids] + [id[0] for id in commented_author_ids])
    
    if not followed_ids:
        # If no followed authors, return empty
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'posts': [], 'has_next': False, 'has_prev': False, 'page': 1})
        return render_template('following.html', posts=None)
    
    # Get posts from followed authors
    following_posts = Post.query.filter(
        Post.author_id.in_(followed_ids),
        Post.is_blocked == False
    ).join(User).filter(
        User.is_banned == False
    ).order_by(Post.date_pub.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({
            'posts': [{
                'id': post.id,
                'title': post.title,
                'excerpt': post.desc[:120] + '...' if len(post.desc) > 120 else post.desc,
                'image_url': post.image_url,
                'author': post.author.username,
                'date': post.date_pub.strftime('%b %d, %Y'),
                'views': post.views,
                'likes': post.like_count,
                'comments': post.comment_count,
                'category': post.category_obj.name if post.category_obj else 'General',
                'url': url_for('admin.see_more', post_id=post.id)
            } for post in following_posts.items],
            'has_next': following_posts.has_next,
            'has_prev': following_posts.has_prev,
            'page': page
        })
    
    return render_template('following.html', posts=following_posts)


# PRODUCTION-GRADE TRENDING ALGORITHM
# Based on Reddit's Hot Ranking Algorithm + Engagement Metrics

#coment
This implements a sophisticated trending algorithm that considers:
1. Engagement Score (views, likes, comments, shares)
2. Time Decay (recent posts rank higher)
3. Velocity (how fast engagement is growing)
4. Quality Signals (comment/like ratio, read time)
5. Personalization (category preferences, author following)

Formula: 
Trending Score = (Engagement Score * Recency Weight * Velocity Multiplier) / Time Decay Factor

Similar to algorithms used by:
- Reddit (Hot ranking)
- Hacker News (Front page algorithm)
- Medium (Recommended stories)
- Twitter (What's Happening)
"""


@main.route('/trending')
def trending():
    """
    Production-grade trending algorithm with time decay and engagement scoring
    """
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    category_id = request.args.get('category', type=int)
    time_range = request.args.get('range', 'week')  # hour, day, week, month, all
    
    # Define time ranges
    time_ranges = {
        'hour': timedelta(hours=1),
        'day': timedelta(days=1),
        'week': timedelta(days=7),
        'month': timedelta(days=30),
        'all': timedelta(days=365)
    }
    
    cutoff_time = datetime.utcnow() - time_ranges.get(time_range, timedelta(days=7))
    
    # Build the trending query with CTEs for performance
    trending_query = db.session.query(
        Post.id,
        Post.title,
        Post.desc,
        Post.image_url,
        Post.date_pub,
        Post.views,
        Post.like_count,
        Post.author_id,
        Post.category_id,
        User.username.label('author_username'),
        Category.name.label('category_name'),
        
        # Calculate engagement score
        (
            (Post.views * 1.0) +                    # Base views
            (Post.like_count * 3.0) +               # Likes worth 3x views
            (func.count(Comment.id) * 5.0) +        # Comments worth 5x views
            (Post.like_count * 0.1 * Post.views)    # Viral coefficient
        ).label('engagement_score'),
        
        # Calculate time decay (posts lose 50% score every 24 hours)
        func.power(
            0.5,
            func.extract('epoch', func.now() - Post.date_pub) / 86400.0
        ).label('time_decay'),
        
        # Calculate velocity (engagement per hour since publication)
        case(
            (func.extract('epoch', func.now() - Post.date_pub) > 0,
             (Post.views + Post.like_count * 3 + func.count(Comment.id) * 5) / 
             (func.extract('epoch', func.now() - Post.date_pub) / 3600.0)
            ),
            else_=0
        ).label('velocity'),
        
        # Quality signal (comment/like ratio - discussions are valuable)
        case(
            (Post.like_count > 0,
             func.count(Comment.id).cast(db.Float) / Post.like_count
            ),
            else_=0
        ).label('discussion_ratio'),
        
        # Final trending score
        (
            # Engagement component
            (
                (Post.views * 1.0) +
                (Post.like_count * 3.0) +
                (func.count(Comment.id) * 5.0) +
                (Post.like_count * 0.1 * Post.views)
            ) *
            # Time decay component (exponential decay)
            func.power(0.5, func.extract('epoch', func.now() - Post.date_pub) / 86400.0) *
            # Velocity bonus (fast-growing posts get boost)
            (1.0 + func.least(
                case(
                    (func.extract('epoch', func.now() - Post.date_pub) > 0,
                     (Post.views + Post.like_count * 3) / 
                     (func.extract('epoch', func.now() - Post.date_pub) / 3600.0)
                    ),
                    else_=0
                ) / 100.0,
                2.0  # Cap velocity bonus at 2x
            ))
        ).label('trending_score')
    ).select_from(Post).join(
        User, Post.author_id == User.id
    ).outerjoin(
        Category, Post.category_id == Category.id
    ).outerjoin(
        Comment, Post.id == Comment.post_id
    ).filter(
        Post.is_blocked == False,
        User.is_banned == False,
        Post.date_pub >= cutoff_time
    ).group_by(
        Post.id, 
        User.username,
        Category.name
    )
    
    # Apply category filter if specified
    if category_id:
        trending_query = trending_query.filter(Post.category_id == category_id)
    
    # Order by trending score
    trending_query = trending_query.order_by(db.desc('trending_score'))
    
    # Execute and paginate
    try:
        results = trending_query.limit(per_page).offset((page - 1) * per_page).all()
        total = trending_query.count()
        
        posts_data = []
        for result in results:
            # Get the actual post for comment count
            post = Post.query.get(result.id)
            
            posts_data.append({
                'id': result.id,
                'title': result.title,
                'excerpt': result.desc[:120] + '...' if len(result.desc) > 120 else result.desc,
                'image_url': result.image_url,
                'author': result.author_username,
                'category': result.category_name or 'General',
                'date': result.date_pub.strftime('%b %d, %Y'),
                'views': result.views,
                'likes': result.like_count,
                'comments': post.comment_count,
                'url': url_for('admin.see_more', post_id=result.id),
                # Metrics for debugging/display
                'metrics': {
                    'engagement_score': round(float(result.engagement_score or 0), 2),
                    'trending_score': round(float(result.trending_score or 0), 2),
                    'velocity': round(float(result.velocity or 0), 2),
                    'discussion_ratio': round(float(result.discussion_ratio or 0), 2),
                    'age_hours': round((datetime.utcnow() - result.date_pub).total_seconds() / 3600, 1)
                }
            })
        
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({
                'posts': posts_data,
                'has_next': page * per_page < total,
                'has_prev': page > 1,
                'page': page,
                'total': total,
                'algorithm': 'production_grade_v1'
            })
        
        return jsonify({
            'posts': posts_data,
            'has_next': page * per_page < total,
            'has_prev': page > 1,
            'page': page
        })
        
    except Exception as e:
        current_app.logger.error(f"Trending algorithm error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'posts': [],
            'error': 'Algorithm error',
            'has_next': False,
            'has_prev': False,
            'page': 1
        })


@main.route('/following')
@login_required
def following():
    """
    Intelligent following feed with personalization and ranking
    Shows posts from authors you interact with, ranked by engagement and recency
    """
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    try:
        # Build author affinity scores (how much you interact with each author)
        author_affinities = {}
        
        # Weight: Likes = 1 point, Comments = 3 points
        likes = Like.query.filter_by(user_id=current_user.id).all()
        for like in likes:
            if like.post and like.post.author_id != current_user.id:
                author_id = like.post.author_id
                author_affinities[author_id] = author_affinities.get(author_id, 0) + 1
        
        comments = Comment.query.filter_by(user_id=current_user.id).all()
        for comment in comments:
            if comment.post and comment.post.author_id != current_user.id:
                author_id = comment.post.author_id
                author_affinities[author_id] = author_affinities.get(author_id, 0) + 3
        
        if not author_affinities:
            return jsonify({
                'posts': [],
                'has_next': False,
                'has_prev': False,
                'page': 1,
                'message': 'Start liking and commenting to build your following feed'
            })
        
        # Get top followed authors (sorted by affinity)
        top_authors = sorted(author_affinities.items(), key=lambda x: x[1], reverse=True)
        followed_author_ids = [author_id for author_id, _ in top_authors[:100]]  # Top 100
        
        # Query posts from followed authors with ranking
        following_query = db.session.query(
            Post.id,
            Post.title,
            Post.desc,
            Post.image_url,
            Post.date_pub,
            Post.views,
            Post.like_count,
            Post.author_id,
            Post.category_id,
            User.username.label('author_username'),
            Category.name.label('category_name'),
            
            # Personalized score based on author affinity + recency + engagement
            (
                # Author affinity weight (how much you interact with this author)
                case(
                    *[(Post.author_id == aid, affinity * 10) for aid, affinity in author_affinities.items()],
                    else_=0
                ) +
                # Post engagement
                (Post.views * 0.1) +
                (Post.like_count * 2.0) +
                (func.count(Comment.id) * 3.0) +
                # Recency bonus (exponential decay over 7 days)
                (100.0 * func.power(0.5, func.extract('epoch', func.now() - Post.date_pub) / (86400.0 * 7)))
            ).label('personalized_score')
            
        ).select_from(Post).join(
            User, Post.author_id == User.id
        ).outerjoin(
            Category, Post.category_id == Category.id
        ).outerjoin(
            Comment, Post.id == Comment.post_id
        ).filter(
            Post.author_id.in_(followed_author_ids),
            Post.is_blocked == False,
            User.is_banned == False
        ).group_by(
            Post.id,
            User.username,
            Category.name
        ).order_by(
            db.desc('personalized_score')
        )
        
        # Execute query
        results = following_query.limit(per_page).offset((page - 1) * per_page).all()
        total = following_query.count()
        
        posts_data = []
        for result in results:
            post = Post.query.get(result.id)
            
            posts_data.append({
                'id': result.id,
                'title': result.title,
                'excerpt': result.desc[:120] + '...' if len(result.desc) > 120 else result.desc,
                'image_url': result.image_url,
                'author': result.author_username,
                'category': result.category_name or 'General',
                'date': result.date_pub.strftime('%b %d, %Y'),
                'views': result.views,
                'likes': result.like_count,
                'comments': post.comment_count,
                'url': url_for('admin.see_more', post_id=result.id),
                'author_affinity': author_affinities.get(result.author_id, 0),
                'personalized_score': round(float(result.personalized_score or 0), 2)
            })
        
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({
                'posts': posts_data,
                'has_next': page * per_page < total,
                'has_prev': page > 1,
                'page': page,
                'total': total,
                'following_count': len(followed_author_ids),
                'algorithm': 'personalized_feed_v1'
            })
        
        return jsonify({
            'posts': posts_data,
            'has_next': page * per_page < total,
            'has_prev': page > 1,
            'page': page
        })
        
    except Exception as e:
        current_app.logger.error(f"Following feed error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'posts': [],
            'error': 'Feed generation error',
            'has_next': False,
            'has_prev': False,
            'page': 1
        })


@main.route('/api/trending-metrics')
def trending_metrics():
    """
    API endpoint to see how the trending algorithm ranks posts
    Useful for debugging and understanding the algorithm
    """
    post_id = request.args.get('post_id', type=int)
    
    if not post_id:
        return jsonify({'error': 'post_id required'}), 400
    
    post = Post.query.get_or_404(post_id)
    
    # Calculate all metrics
    age_seconds = (datetime.utcnow() - post.date_pub).total_seconds()
    age_hours = age_seconds / 3600
    age_days = age_seconds / 86400
    
    comment_count = post.comments.count()
    
    # Engagement score
    engagement = (
        (post.views * 1.0) +
        (post.like_count * 3.0) +
        (comment_count * 5.0) +
        (post.like_count * 0.1 * post.views)
    )
    
    # Time decay
    time_decay = math.pow(0.5, age_days)
    
    # Velocity
    velocity = (post.views + post.like_count * 3 + comment_count * 5) / max(age_hours, 0.1)
    velocity_bonus = min(velocity / 100.0, 2.0)
    
    # Discussion ratio
    discussion_ratio = comment_count / max(post.like_count, 1)
    
    # Trending score
    trending_score = engagement * time_decay * (1.0 + velocity_bonus)
    
    return jsonify({
        'post': {
            'id': post.id,
            'title': post.title,
            'views': post.views,
            'likes': post.like_count,
            'comments': comment_count,
            'age_hours': round(age_hours, 2),
            'age_days': round(age_days, 2)
        },
        'metrics': {
            'engagement_score': round(engagement, 2),
            'time_decay': round(time_decay, 4),
            'velocity': round(velocity, 2),
            'velocity_bonus': round(velocity_bonus, 2),
            'discussion_ratio': round(discussion_ratio, 2),
            'trending_score': round(trending_score, 2)
        },
        'explanation': {
            'engagement': f"Views({post.views}) + Likes({post.like_count}*3) + Comments({comment_count}*5) + Viral({round(post.like_count * 0.1 * post.views, 2)})",
            'time_decay': f"0.5^({round(age_days, 2)} days) = {round(time_decay, 4)} (50% decay per day)",
            'velocity': f"({post.views} + {post.like_count*3} + {comment_count*5}) / {round(age_hours, 2)} hours = {round(velocity, 2)}",
            'final_score': f"{round(engagement, 2)} * {round(time_decay, 4)} * (1 + {round(velocity_bonus, 2)}) = {round(trending_score, 2)}"
        }
    })
    '''
# SQLITE-COMPATIBLE TRENDING ALGORITHM
# Replace the trending() function in routes.py (around line 530-705)

"""
This version works with SQLite by doing calculations in Python instead of SQL.
Still uses the same production-grade algorithm, just computed after fetching data.
"""

@main.route('/trending')
def trending():
    """
    Production-grade trending algorithm - SQLite compatible
    Calculates scores in Python to avoid SQLite function limitations
    """
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    category_id = request.args.get('category', type=int)
    time_range = request.args.get('range', 'week')
    
    # Define time ranges
    time_ranges = {
        'hour': timedelta(hours=1),
        'day': timedelta(days=1),
        'week': timedelta(days=7),
        'month': timedelta(days=30),
        'all': timedelta(days=365)
    }
    
    cutoff_time = datetime.utcnow() - time_ranges.get(time_range, timedelta(days=7))
    
    try:
        # Fetch all posts in time range with basic info
        query = db.session.query(
            Post.id,
            Post.title,
            Post.desc,
            Post.image_url,
            Post.date_pub,
            Post.views,
            Post.like_count,
            Post.author_id,
            Post.category_id,
            User.username.label('author_username'),
            Category.name.label('category_name'),
            func.count(Comment.id).label('comment_count')
        ).select_from(Post).join(
            User, Post.author_id == User.id
        ).outerjoin(
            Category, Post.category_id == Category.id
        ).outerjoin(
            Comment, Post.id == Comment.post_id
        ).filter(
            Post.is_blocked == False,
            User.is_banned == False,
            Post.date_pub >= cutoff_time
        ).group_by(
            Post.id,
            Post.title,
            Post.desc,
            Post.image_url,
            Post.date_pub,
            Post.views,
            Post.like_count,
            Post.author_id,
            Post.category_id,
            User.username,
            Category.name
        )
        
        # Apply category filter if specified
        if category_id:
            query = query.filter(Post.category_id == category_id)
        
        # Fetch all results
        all_results = query.all()
        
        # Calculate trending scores in Python
        scored_posts = []
        current_time = datetime.utcnow()
        
        for result in all_results:
            # Calculate age in seconds
            age_seconds = (current_time - result.date_pub).total_seconds()
            age_hours = age_seconds / 3600.0
            age_days = age_seconds / 86400.0
            
            # Skip if age is 0 (shouldn't happen, but safety check)
            if age_seconds <= 0:
                age_seconds = 1
                age_hours = 1 / 3600.0
                age_days = 1 / 86400.0
            
            # 1. ENGAGEMENT SCORE
            views = result.views or 0
            likes = result.like_count or 0
            comments = result.comment_count or 0
            
            engagement_score = (
                (views * 1.0) +           # Base views
                (likes * 3.0) +           # Likes worth 3x
                (comments * 5.0) +        # Comments worth 5x
                (likes * 0.1 * views)     # Viral coefficient
            )
            
            # 2. TIME DECAY (exponential: 50% decay per day)
            # Formula: 0.5^(age_in_days)
            time_decay = math.pow(0.5, age_days)
            
            # 3. VELOCITY (engagement per hour)
            velocity = (views + likes * 3 + comments * 5) / age_hours
            
            # Velocity bonus (capped at 2x)
            velocity_bonus = min(velocity / 100.0, 2.0)
            
            # 4. DISCUSSION RATIO (quality signal)
            discussion_ratio = comments / max(likes, 1)
            
            # 5. FINAL TRENDING SCORE
            trending_score = engagement_score * time_decay * (1.0 + velocity_bonus)
            
            scored_posts.append({
                'id': result.id,
                'title': result.title,
                'desc': result.desc,
                'image_url': result.image_url,
                'date_pub': result.date_pub,
                'views': views,
                'likes': likes,
                'comments': comments,
                'author_username': result.author_username,
                'category_name': result.category_name or 'General',
                'engagement_score': engagement_score,
                'time_decay': time_decay,
                'velocity': velocity,
                'velocity_bonus': velocity_bonus,
                'discussion_ratio': discussion_ratio,
                'trending_score': trending_score,
                'age_hours': age_hours
            })
        
        # Sort by trending score (highest first)
        scored_posts.sort(key=lambda x: x['trending_score'], reverse=True)
        
        # Paginate in Python
        total = len(scored_posts)
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        paginated_posts = scored_posts[start_idx:end_idx]
        
        # Format for response
        posts_data = []
        for post in paginated_posts:
            posts_data.append({
                'id': post['id'],
                'title': post['title'],
                'excerpt': post['desc'][:120] + '...' if len(post['desc']) > 120 else post['desc'],
                'image_url': post['image_url'],
                'author': post['author_username'],
                'category': post['category_name'],
                'date': post['date_pub'].strftime('%b %d, %Y'),
                'views': post['views'],
                'likes': post['likes'],
                'comments': post['comments'],
                'url': url_for('admin.see_more', post_id=post['id']),
                'metrics': {
                    'engagement_score': round(post['engagement_score'], 2),
                    'trending_score': round(post['trending_score'], 2),
                    'velocity': round(post['velocity'], 2),
                    'velocity_bonus': round(post['velocity_bonus'], 2),
                    'discussion_ratio': round(post['discussion_ratio'], 2),
                    'time_decay': round(post['time_decay'], 4),
                    'age_hours': round(post['age_hours'], 1)
                }
            })
        
        # Return response
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({
                'posts': posts_data,
                'has_next': end_idx < total,
                'has_prev': page > 1,
                'page': page,
                'total': total,
                'algorithm': 'production_grade_sqlite_v1'
            })
        
        return jsonify({
            'posts': posts_data,
            'has_next': end_idx < total,
            'has_prev': page > 1,
            'page': page,
            'total': total
        })
        
    except Exception as e:
        current_app.logger.error(f"Trending algorithm error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'posts': [],
            'error': 'Algorithm error',
            'has_next': False,
            'has_prev': False,
            'page': 1,
            'total': 0
        })


# BONUS: Enhanced following route for SQLite
@main.route('/following')
@login_required
def following():
    """
    Personalized following feed - SQLite compatible
    """
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    try:
        # Get author affinities (likes = 1 point, comments = 3 points)
        author_affinities = {}
        
        # Get liked posts
        likes = Like.query.filter_by(user_id=current_user.id).all()
        for like in likes:
            if like.post and like.post.author_id != current_user.id:
                author_id = like.post.author_id
                author_affinities[author_id] = author_affinities.get(author_id, 0) + 1
        
        # Get commented posts
        comments = Comment.query.filter_by(user_id=current_user.id).all()
        for comment in comments:
            if comment.post and comment.post.author_id != current_user.id:
                author_id = comment.post.author_id
                author_affinities[author_id] = author_affinities.get(author_id, 0) + 3
        
        if not author_affinities:
            return jsonify({
                'posts': [],
                'has_next': False,
                'has_prev': False,
                'page': 1,
                'total': 0,
                'message': 'Start liking and commenting to build your following feed'
            })
        
        # Get posts from followed authors
        followed_author_ids = list(author_affinities.keys())
        
        # Fetch posts
        query = db.session.query(
            Post.id,
            Post.title,
            Post.desc,
            Post.image_url,
            Post.date_pub,
            Post.views,
            Post.like_count,
            Post.author_id,
            Post.category_id,
            User.username.label('author_username'),
            Category.name.label('category_name'),
            func.count(Comment.id).label('comment_count')
        ).select_from(Post).join(
            User, Post.author_id == User.id
        ).outerjoin(
            Category, Post.category_id == Category.id
        ).outerjoin(
            Comment, Post.id == Comment.post_id
        ).filter(
            Post.author_id.in_(followed_author_ids),
            Post.is_blocked == False,
            User.is_banned == False
        ).group_by(
            Post.id,
            Post.title,
            Post.desc,
            Post.image_url,
            Post.date_pub,
            Post.views,
            Post.like_count,
            Post.author_id,
            Post.category_id,
            User.username,
            Category.name
        )
        
        all_results = query.all()
        
        # Calculate personalized scores
        scored_posts = []
        current_time = datetime.utcnow()
        
        for result in all_results:
            # Author affinity weight
            affinity_score = author_affinities.get(result.author_id, 0) * 10
            
            # Post engagement
            engagement = (result.views or 0) * 0.1 + (result.like_count or 0) * 2.0 + (result.comment_count or 0) * 3.0
            
            # Recency bonus (weekly decay instead of daily)
            age_weeks = (current_time - result.date_pub).total_seconds() / (86400.0 * 7)
            recency_bonus = 100.0 * math.pow(0.5, age_weeks)
            
            # Personalized score
            personalized_score = affinity_score + engagement + recency_bonus
            
            scored_posts.append({
                'id': result.id,
                'title': result.title,
                'desc': result.desc,
                'image_url': result.image_url,
                'date_pub': result.date_pub,
                'views': result.views or 0,
                'likes': result.like_count or 0,
                'comments': result.comment_count or 0,
                'author_username': result.author_username,
                'category_name': result.category_name or 'General',
                'author_affinity': author_affinities.get(result.author_id, 0),
                'personalized_score': personalized_score
            })
        
        # Sort by personalized score
        scored_posts.sort(key=lambda x: x['personalized_score'], reverse=True)
        
        # Paginate
        total = len(scored_posts)
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        paginated_posts = scored_posts[start_idx:end_idx]
        
        # Format response
        posts_data = []
        for post in paginated_posts:
            posts_data.append({
                'id': post['id'],
                'title': post['title'],
                'excerpt': post['desc'][:120] + '...' if len(post['desc']) > 120 else post['desc'],
                'image_url': post['image_url'],
                'author': post['author_username'],
                'category': post['category_name'],
                'date': post['date_pub'].strftime('%b %d, %Y'),
                'views': post['views'],
                'likes': post['likes'],
                'comments': post['comments'],
                'url': url_for('admin.see_more', post_id=post['id']),
                'author_affinity': post['author_affinity'],
                'personalized_score': round(post['personalized_score'], 2)
            })
        
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({
                'posts': posts_data,
                'has_next': end_idx < total,
                'has_prev': page > 1,
                'page': page,
                'total': total,
                'following_count': len(followed_author_ids),
                'algorithm': 'personalized_feed_sqlite_v1'
            })
        
        return jsonify({
            'posts': posts_data,
            'has_next': end_idx < total,
            'has_prev': page > 1,
            'page': page,
            'total': total
        })
        
    except Exception as e:
        current_app.logger.error(f"Following feed error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'posts': [],
            'error': 'Feed generation error',
            'has_next': False,
            'has_prev': False,
            'page': 1,
            'total': 0
        })


# BONUS: Debug endpoint to see algorithm metrics
@main.route('/api/trending-debug/<int:post_id>')
def trending_debug(post_id):
    """
    Debug endpoint showing how a post is scored
    """
    try:
        post = Post.query.get_or_404(post_id)
        
        # Calculate metrics
        current_time = datetime.utcnow()
        age_seconds = (current_time - post.date_pub).total_seconds()
        age_hours = age_seconds / 3600.0
        age_days = age_seconds / 86400.0
        
        if age_seconds <= 0:
            age_seconds = age_hours = age_days = 1
        
        views = post.views or 0
        likes = post.like_count or 0
        comments = post.comment_count or 0
        
        engagement_score = (views * 1.0) + (likes * 3.0) + (comments * 5.0) + (likes * 0.1 * views)
        time_decay = math.pow(0.5, age_days)
        velocity = (views + likes * 3 + comments * 5) / age_hours
        velocity_bonus = min(velocity / 100.0, 2.0)
        discussion_ratio = comments / max(likes, 1)
        trending_score = engagement_score * time_decay * (1.0 + velocity_bonus)
        
        return jsonify({
            'post': {
                'id': post.id,
                'title': post.title,
                'views': views,
                'likes': likes,
                'comments': comments,
                'age_hours': round(age_hours, 2),
                'age_days': round(age_days, 2)
            },
            'metrics': {
                'engagement_score': round(engagement_score, 2),
                'time_decay': round(time_decay, 4),
                'velocity': round(velocity, 2),
                'velocity_bonus': round(velocity_bonus, 2),
                'discussion_ratio': round(discussion_ratio, 2),
                'trending_score': round(trending_score, 2)
            },
            'formula': {
                'engagement': f"{views} + ({likes} × 3) + ({comments} × 5) + ({likes} × 0.1 × {views}) = {round(engagement_score, 2)}",
                'time_decay': f"0.5^{round(age_days, 2)} = {round(time_decay, 4)}",
                'velocity': f"({views} + {likes*3} + {comments*5}) / {round(age_hours, 2)}h = {round(velocity, 2)}",
                'velocity_bonus': f"min({round(velocity/100, 2)}, 2.0) = {round(velocity_bonus, 2)}",
                'final': f"{round(engagement_score, 2)} × {round(time_decay, 4)} × (1 + {round(velocity_bonus, 2)}) = {round(trending_score, 2)}"
            }
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@main.route('/api/comment/add/<int:post_id>', methods=['POST'])
@login_required
def add_comment_ajax(post_id):
    """Add comment via AJAX"""
    try:
        data = request.get_json()
        content = data.get('content', '').strip()
        
        if not content:
            return jsonify({
                'success': False,
                'message': 'Comment cannot be empty'
            }), 400
        
        if len(content) > 1000:
            return jsonify({
                'success': False,
                'message': 'Comment too long (max 1000 characters)'
            }), 400
        
        # Check for spam (simple check)
        spam_words = ['viagra', 'casino', 'lottery', 'click here', 'buy now']
        if any(word in content.lower() for word in spam_words):
            return jsonify({
                'success': False,
                'message': 'Comment contains inappropriate content'
            }), 400
        
        # Create comment
        comment = Comment(
            content=content,
            user_id=current_user.id,
            post_id=post_id
        )
        
        db.session.add(comment)
        db.session.commit()
        
        # Update post comment count
        post = Post.query.get(post_id)
        
        return jsonify({
            'success': True,
            'message': 'Comment added successfully',
            'comment': comment.to_dict(),
            'comment_count': post.comment_count
        })
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error adding comment: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Error adding comment'
        }), 500


# AJAX: Edit comment
@main.route('/api/comment/edit/<int:comment_id>', methods=['PUT'])
@login_required
def edit_comment_ajax(comment_id):
    """Edit comment via AJAX"""
    try:
        comment = Comment.query.get_or_404(comment_id)
        
        # Check permission
        if comment.user_id != current_user.id and not current_user.is_admin:
            return jsonify({
                'success': False,
                'message': 'Unauthorized'
            }), 403
        
        data = request.get_json()
        content = data.get('content', '').strip()
        
        if not content:
            return jsonify({
                'success': False,
                'message': 'Comment cannot be empty'
            }), 400
        
        comment.content = content
        comment.edited = True
        comment.edited_at = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Comment updated successfully',
            'comment': comment.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error editing comment: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Error editing comment'
        }), 500


# AJAX: Delete comment
@main.route('/api/comment/delete/<int:comment_id>', methods=['DELETE'])
@login_required
def delete_comment_ajax(comment_id):
    """Delete comment via AJAX"""
    try:
        comment = Comment.query.get_or_404(comment_id)
        
        # Check permission
        if comment.user_id != current_user.id and not current_user.is_admin:
            return jsonify({
                'success': False,
                'message': 'Unauthorized'
            }), 403
        
        post_id = comment.post_id
        db.session.delete(comment)
        db.session.commit()
        
        # Get updated comment count
        post = Post.query.get(post_id)
        
        return jsonify({
            'success': True,
            'message': 'Comment deleted successfully',
            'comment_count': post.comment_count
        })
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error deleting comment: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Error deleting comment'
        }), 500


# AJAX: Flag comment (Admin only)
@main.route('/api/comment/flag/<int:comment_id>', methods=['POST'])
@login_required
def flag_comment(comment_id):
    """Flag comment as inappropriate (Admin only)"""
    if not current_user.is_admin:
        return jsonify({
            'success': False,
            'message': 'Unauthorized'
        }), 403
    
    try:
        comment = Comment.query.get_or_404(comment_id)
        data = request.get_json()
        
        action = data.get('action', 'flag')  # 'flag', 'unflag', 'hide', 'unhide'
        reason = data.get('reason', 'Inappropriate content')
        
        if action == 'flag':
            comment.is_flagged = True
            comment.flag_reason = reason
            comment.flagged_by = current_user.id
            comment.flagged_at = datetime.utcnow()
            message = 'Comment flagged successfully'
            
        elif action == 'unflag':
            comment.is_flagged = False
            comment.flag_reason = None
            comment.flagged_by = None
            comment.flagged_at = None
            message = 'Comment unflagged successfully'
            
        elif action == 'hide':
            comment.is_hidden = True
            message = 'Comment hidden successfully'
            
        elif action == 'unhide':
            comment.is_hidden = False
            message = 'Comment unhidden successfully'
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': message,
            'comment': comment.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error flagging comment: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Error processing request'
        }), 500


# AJAX: Get comments for a post
@main.route('/api/comments/<int:post_id>')
def get_comments(post_id):
    """Get all comments for a post"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        
        # Get comments (show hidden only to admins)
        query = Comment.query.filter_by(post_id=post_id)
        
        if not (current_user.is_authenticated and current_user.is_admin):
            query = query.filter_by(is_hidden=False)
        
        comments = query.order_by(Comment.date_posted.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        return jsonify({
            'success': True,
            'comments': [comment.to_dict() for comment in comments.items],
            'total': comments.total,
            'pages': comments.pages,
            'current_page': page,
            'has_next': comments.has_next,
            'has_prev': comments.has_prev
        })
        
    except Exception as e:
        current_app.logger.error(f"Error getting comments: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Error loading comments'
        }), 500


@main.route('/delete_comment/<int:comment_id>', methods=['POST'])
@login_required
def delete_comment(comment_id):
    """Legacy delete route (redirects)"""
    comment = Comment.query.get_or_404(comment_id)
    if comment.user_id == current_user.id or current_user.is_admin:
        post_id = comment.post_id
        db.session.delete(comment)
        db.session.commit()
        flash('Comment deleted', 'success')
        return redirect(url_for('admin.see_more', post_id=post_id))
    flash('Unauthorized', 'danger')
    return redirect(url_for('main.index'))


