# app/utils.py
import bleach
from app.models import Post, User
from flask import url_for
import hashlib
import os

def allowed_file(filename, extensions=None):
    if not extensions:
        extensions = ['jpg', 'jpeg', 'png', 'gif']
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in extensions



def get_avatar_url(email, username, size=32):
    """
    Generate a Gravatar URL or fallback to UI Avatars based on email or username
    """
    if email:
        # Try Gravatar first
        email_hash = hashlib.md5(email.lower().encode('utf-8')).hexdigest()
        gravatar_url = f"https://www.gravatar.com/avatar/{email_hash}?s={size}&d=identicon"
        return gravatar_url
    else:
        # Fallback to UI Avatars
        return f"https://ui-avatars.com/api/?name={username}&background=random&size={size}"

def get_recommended_posts(current_post_id=None, limit=3):
    """
    Get recommended posts for popups
    """
    # Get posts that are not blocked and from non-banned users
    base_query = Post.query.join(User).filter(
        User.is_banned == False, 
        Post.is_blocked == False
    )
    
    # Exclude current post if provided
    if current_post_id:
        base_query = base_query.filter(Post.id != current_post_id)
    
    # Get posts with highest views or likes, fallback to newest
    recommended = base_query.order_by(
        Post.views.desc(), 
        Post.like_count.desc(), 
        Post.id.desc()
    ).limit(limit).all()
    
    # If not enough posts, get the newest ones
    if len(recommended) < limit:
        additional = base_query.order_by(Post.id.desc()).limit(limit - len(recommended)).all()
        recommended.extend(additional)
    
    # Prepare data for JSON serialization
    recommended_data = []
    for post in recommended:
        # Clean HTML from description
        clean_desc = bleach.clean(post.desc or '', tags=[], strip=True)
        recommended_data.append({
            'id': post.id,
            'title': post.title,
            'desc': clean_desc[:150] + '...' if len(clean_desc) > 150 else clean_desc,
            'image_url': post.image_url or '',
            'url': url_for('admin.see_more', post_id=post.id, _external=False)
        })
    
    return recommended_data
