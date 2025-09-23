import os
import secrets
import bleach
from flask import Blueprint, request, jsonify, current_app
from flask_login import current_user
from app import db
from app.models import Post, Category, ApiKey, User
from app.utils import allowed_file
from werkzeug.utils import secure_filename
from app.admin_routes import admin_required
from functools import wraps

api_bp = Blueprint('api', __name__)

# API key authentication decorator
def api_key_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
        
        if not api_key:
            return jsonify({'error': 'API key required'}), 401
            
        # Check if API key exists and is active
        key_record = ApiKey.query.filter_by(key=api_key, is_active=True).first()
        if not key_record:
            return jsonify({'error': 'Invalid API key'}), 401
            
        # Check if user has posting permission
        if 'post:create' not in key_record.permissions.split(','):
            return jsonify({'error': 'Insufficient permissions'}), 403
            
        # Attach the user to the request for later use
        request.api_user = key_record.user
        return f(*args, **kwargs)
    return decorated_function

# Generate a new API key
@api_bp.route('/api/generate_key', methods=['POST'])
@admin_required  # Only admins can generate API keys
def generate_api_key():
    user_id = request.json.get('user_id')
    permissions = request.json.get('permissions', 'post:create')
    
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
        
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
    
    return jsonify({
        'api_key': api_key,
        'user_id': user_id,
        'permissions': permissions
    }), 201

# Create a post via API
@api_bp.route('/api/posts', methods=['POST'])
@api_key_required
def create_post():
    try:
        # Get data from request
        title = request.form.get('title', '').strip()
        content = request.form.get('content', '').strip()
        category_id = request.form.get('category_id')
        
        if not title or not content:
            return jsonify({'error': 'Title and content are required'}), 400
            
        # Sanitize content
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
        sanitized_content = bleach.clean(content, tags=allowed_tags, attributes=allowed_attributes, strip=True)
        
        # Handle image upload if provided
        filename = None
        if 'image' in request.files:
            file = request.files['image']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
        
        # Get category if provided
        category = None
        if category_id:
            category = Category.query.get(category_id)
        
        # Create post
        post = Post(
            title=title,
            desc=sanitized_content,
            category_obj=category,
            image_url=filename,
            author=request.api_user
        )
        
        db.session.add(post)
        db.session.commit()
        
        return jsonify({
            'message': 'Post created successfully',
            'post_id': post.id,
            'post_url': f"{request.host_url}see_more/{post.id}"
        }), 201
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"API post creation error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

# Get list of posts via API
@api_bp.route('/api/posts', methods=['GET'])
@api_key_required
def get_posts():
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        
        # Only return posts by the API user
        posts = Post.query.filter_by(author=request.api_user)\
                         .order_by(Post.date_pub.desc())\
                         .paginate(page=page, per_page=per_page, error_out=False)
        
        posts_data = []
        for post in posts.items:
            posts_data.append({
                'id': post.id,
                'title': post.title,
                'excerpt': post.desc[:100] + '...' if len(post.desc) > 100 else post.desc,
                'published_date': post.date_pub,
                'views': post.views,
                'likes': post.like_count,
                'url': f"{request.host_url}see_more/{post.id}"
            })
        
        return jsonify({
            'posts': posts_data,
            'total': posts.total,
            'pages': posts.pages,
            'current_page': page
        })
        
    except Exception as e:
        current_app.logger.error(f"API get posts error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

# Get categories for dropdown
@api_bp.route('/api/categories', methods=['GET'])
@api_key_required
def get_categories():
    try:
        categories = Category.query.order_by(Category.name).all()
        categories_data = [{'id': cat.id, 'name': cat.name} for cat in categories]
        
        return jsonify({'categories': categories_data})
        
    except Exception as e:
        current_app.logger.error(f"API get categories error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500
