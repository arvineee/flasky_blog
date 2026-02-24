import os
import secrets
import bleach
from flask import Blueprint, request, jsonify, current_app
from flask_login import current_user
from app import db
from app.models import Post, Category, ApiKey, User, Video
from app.utils import allowed_file
from werkzeug.utils import secure_filename
from app.admin_routes import admin_required
from functools import wraps

api_bp = Blueprint('api', __name__)

# ── Allowed Extensions ────────────────────────────────────────────────────────
IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
VIDEO_EXTENSIONS = {'mp4', 'webm', 'mov', 'avi', 'mkv'}

def allowed_image(filename):
    return allowed_file(filename, IMAGE_EXTENSIONS)

def allowed_video(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in VIDEO_EXTENSIONS

# ── API Key Auth Decorator ────────────────────────────────────────────────────
def api_key_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
        if not api_key:
            return jsonify({'error': 'API key required'}), 401
        key_record = ApiKey.query.filter_by(key=api_key, is_active=True).first()
        if not key_record:
            return jsonify({'error': 'Invalid or inactive API key'}), 401
        if 'post:create' not in key_record.permissions.split(','):
            return jsonify({'error': 'Insufficient permissions'}), 403
        request.api_user = key_record.user
        return f(*args, **kwargs)
    return decorated_function


# ── Helper: resolve category from ID or name ─────────────────────────────────
def _resolve_category(category_id=None, category_name=None):
    if category_id:
        return Category.query.get(int(category_id))
    if category_name:
        cat = Category.query.filter(
            db.func.lower(Category.name) == category_name.strip().lower()
        ).first()
        if not cat:
            cat = Category(name=category_name.strip().title())
            db.session.add(cat)
            db.session.flush()
        return cat
    return None


# ═══════════════════════════════════════════════════════════════════════════════
# KEY MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════════

@api_bp.route('/api/generate_key', methods=['POST'])
@admin_required
def generate_api_key():
    """Generate a new API key (admin only)."""
    user_id = request.json.get('user_id')
    permissions = request.json.get('permissions', 'post:create')
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    api_key = secrets.token_urlsafe(32)
    key_record = ApiKey(key=api_key, user_id=user_id, permissions=permissions)
    db.session.add(key_record)
    db.session.commit()
    return jsonify({'api_key': api_key, 'user_id': user_id, 'permissions': permissions}), 201


# ═══════════════════════════════════════════════════════════════════════════════
# POSTS
# ═══════════════════════════════════════════════════════════════════════════════

@api_bp.route('/api/posts', methods=['POST'])
@api_key_required
def create_post():
    """
    Create a new post with optional image and/or video.

    Form fields:
        title          (str, required)
        content        (str, required) – HTML allowed
        category_id    (int, optional) – category by numeric ID
        category_name  (str, optional) – category by name; auto-creates if absent
        image          (file, optional) – jpg / png / gif / webp
        video          (file, optional) – mp4 / webm / mov / avi / mkv
        video_url      (str, optional)  – already-stored video filename
    """
    try:
        title = request.form.get('title', '').strip()
        content = request.form.get('content', '').strip()
        category_id = request.form.get('category_id')
        category_name = request.form.get('category_name')
        video_url_field = request.form.get('video_url', '').strip()

        if not title or not content:
            return jsonify({'error': 'title and content are required'}), 400

        allowed_tags = [
            'p', 'strong', 'em', 'a', 'ul', 'ol', 'li', 'br', 'u', 'i', 'b',
            'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'blockquote', 'code', 'pre',
            'img', 'hr', 'table', 'tr', 'th', 'td'
        ]
        allowed_attributes = {
            'a': ['href', 'title'], 'img': ['src', 'alt', 'title', 'style'],
            'table': ['class', 'border'], 'tr': ['class'], 'th': ['class', 'scope'], 'td': ['class']
        }
        sanitized_content = bleach.clean(content, tags=allowed_tags, attributes=allowed_attributes, strip=True)

        # Handle image upload
        image_filename = None
        if 'image' in request.files:
            img = request.files['image']
            if img and img.filename and allowed_image(img.filename):
                image_filename = secure_filename(img.filename)
                img.save(os.path.join(current_app.config['UPLOAD_FOLDER'], image_filename))
            elif img and img.filename:
                return jsonify({'error': 'Invalid image format. Allowed: png, jpg, jpeg, gif, webp'}), 400

        # Handle video upload
        video_filename = video_url_field or None
        if 'video' in request.files:
            vid = request.files['video']
            if vid and vid.filename and allowed_video(vid.filename):
                video_filename = secure_filename(vid.filename)
                video_folder = os.path.join(current_app.config['UPLOAD_FOLDER'], '..', 'videos')
                os.makedirs(video_folder, exist_ok=True)
                vid.save(os.path.join(video_folder, video_filename))
            elif vid and vid.filename:
                return jsonify({'error': 'Invalid video format. Allowed: mp4, webm, mov, avi, mkv'}), 400

        category = _resolve_category(category_id, category_name)

        post = Post(
            title=title,
            desc=sanitized_content,
            category_obj=category,
            image_url=image_filename,
            video_url=video_filename,
            author=request.api_user
        )
        db.session.add(post)
        db.session.commit()

        return jsonify({
            'message': 'Post created successfully',
            'post_id': post.id,
            'post_url': f"{request.host_url}see_more/{post.id}",
            'has_video': video_filename is not None,
            'category': {'id': category.id, 'name': category.name} if category else None
        }), 201

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"API create_post error: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@api_bp.route('/api/posts', methods=['GET'])
@api_key_required
def get_posts():
    """
    List posts belonging to the authenticated API user.

    Query params:
        page          (int, default 1)
        per_page      (int, default 10, max 50)
        category_id   (int, optional)  – filter by category ID
        category      (str, optional)  – filter by category name (partial, case-insensitive)
        has_video     (str, optional)  – pass '1' to return only posts with video
    """
    try:
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 10, type=int), 50)
        category_id_filter = request.args.get('category_id', type=int)
        category_name_filter = request.args.get('category', type=str)
        has_video = request.args.get('has_video')

        query = Post.query.filter_by(author=request.api_user)

        if category_id_filter:
            query = query.filter(Post.category_id == category_id_filter)
        elif category_name_filter:
            query = query.join(Category).filter(Category.name.ilike(f'%{category_name_filter}%'))

        if has_video == '1':
            query = query.filter(Post.video_url.isnot(None))

        posts = query.order_by(Post.date_pub.desc()).paginate(page=page, per_page=per_page, error_out=False)

        posts_data = [{
            'id': p.id,
            'title': p.title,
            'excerpt': p.desc[:150] + '...' if len(p.desc) > 150 else p.desc,
            'published_date': p.date_pub.isoformat(),
            'views': p.views,
            'likes': p.like_count,
            'comments': p.comment_count,
            'has_video': p.video_url is not None,
            'video_url': p.video_url,
            'image_url': p.image_url,
            'category': {'id': p.category_obj.id, 'name': p.category_obj.name} if p.category_obj else None,
            'url': f"{request.host_url}see_more/{p.id}"
        } for p in posts.items]

        return jsonify({
            'posts': posts_data,
            'total': posts.total,
            'pages': posts.pages,
            'current_page': page,
            'has_next': posts.has_next,
            'has_prev': posts.has_prev
        })

    except Exception as e:
        current_app.logger.error(f"API get_posts error: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@api_bp.route('/api/posts/<int:post_id>', methods=['GET'])
@api_key_required
def get_post(post_id):
    """Get a single post by ID (must belong to the authenticated user)."""
    post = Post.query.filter_by(id=post_id, author=request.api_user).first()
    if not post:
        return jsonify({'error': 'Post not found'}), 404
    return jsonify({
        'id': post.id,
        'title': post.title,
        'content': post.desc,
        'published_date': post.date_pub.isoformat(),
        'views': post.views,
        'likes': post.like_count,
        'comments': post.comment_count,
        'image_url': post.image_url,
        'video_url': post.video_url,
        'has_video': post.video_url is not None,
        'category': {'id': post.category_obj.id, 'name': post.category_obj.name} if post.category_obj else None,
        'url': f"{request.host_url}see_more/{post.id}"
    })


# ═══════════════════════════════════════════════════════════════════════════════
# VIDEOS  (standalone Video model)
# ═══════════════════════════════════════════════════════════════════════════════

@api_bp.route('/api/videos', methods=['POST'])
@api_key_required
def create_video():
    """
    Upload a standalone video.

    Form fields:
        title        (str, required)
        description  (str, required)
        video        (file, required) – mp4 / webm / mov / avi / mkv
    """
    try:
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()

        if not title or not description:
            return jsonify({'error': 'title and description are required'}), 400

        if 'video' not in request.files or not request.files['video'].filename:
            return jsonify({'error': 'video file is required'}), 400

        vid = request.files['video']
        if not allowed_video(vid.filename):
            return jsonify({'error': 'Invalid video format. Allowed: mp4, webm, mov, avi, mkv'}), 400

        video_filename = secure_filename(vid.filename)
        video_folder = os.path.join(current_app.config['UPLOAD_FOLDER'], '..', 'videos')
        os.makedirs(video_folder, exist_ok=True)
        vid.save(os.path.join(video_folder, video_filename))

        video = Video(
            title=title,
            description=description,
            video_url=video_filename,
            author=request.api_user
        )
        db.session.add(video)
        db.session.commit()

        return jsonify({
            'message': 'Video uploaded successfully',
            'video_id': video.id,
            'video_url': video_filename
        }), 201

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"API create_video error: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@api_bp.route('/api/videos', methods=['GET'])
@api_key_required
def get_videos():
    """
    List videos belonging to the authenticated API user.

    Query params:
        page     (int, default 1)
        per_page (int, default 10, max 50)
    """
    try:
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 10, type=int), 50)

        videos = Video.query.filter_by(author=request.api_user)\
                            .order_by(Video.upload_time.desc())\
                            .paginate(page=page, per_page=per_page, error_out=False)

        videos_data = [{
            'id': v.id,
            'title': v.title,
            'description': v.description,
            'video_url': v.video_url,
            'uploaded_at': v.upload_time.isoformat()
        } for v in videos.items]

        return jsonify({
            'videos': videos_data,
            'total': videos.total,
            'pages': videos.pages,
            'current_page': page,
            'has_next': videos.has_next,
            'has_prev': videos.has_prev
        })

    except Exception as e:
        current_app.logger.error(f"API get_videos error: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@api_bp.route('/api/videos/<int:video_id>', methods=['DELETE'])
@api_key_required
def delete_video(video_id):
    """Delete a video by ID (must belong to the authenticated user)."""
    video = Video.query.filter_by(id=video_id, author=request.api_user).first()
    if not video:
        return jsonify({'error': 'Video not found'}), 404
    try:
        video_path = os.path.join(current_app.config['UPLOAD_FOLDER'], '..', 'videos', video.video_url)
        if os.path.exists(video_path):
            os.remove(video_path)
        db.session.delete(video)
        db.session.commit()
        return jsonify({'message': 'Video deleted successfully'})
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"API delete_video error: {e}")
        return jsonify({'error': 'Internal server error'}), 500


# ═══════════════════════════════════════════════════════════════════════════════
# CATEGORIES
# ═══════════════════════════════════════════════════════════════════════════════

@api_bp.route('/api/categories', methods=['GET'])
@api_key_required
def get_categories():
    """
    List all categories.

    Query params:
        flat  (str, optional) – pass '1' to return a flat list instead of tree
    """
    try:
        flat = request.args.get('flat') == '1'
        categories = Category.query.order_by(Category.name).all()

        if flat:
            data = [{'id': c.id, 'name': c.name, 'parent_id': c.parent_id} for c in categories]
            return jsonify({'categories': data, 'total': len(data)})

        def cat_to_dict(cat):
            return {
                'id': cat.id,
                'name': cat.name,
                'parent_id': cat.parent_id,
                'children': [cat_to_dict(c) for c in cat.children]
            }

        roots = [cat_to_dict(c) for c in categories if c.parent_id is None]
        return jsonify({'categories': roots, 'total': len(categories)})

    except Exception as e:
        current_app.logger.error(f"API get_categories error: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@api_bp.route('/api/categories', methods=['POST'])
@api_key_required
def create_category():
    """
    Create a new category.

    JSON body:
        name       (str, required)
        parent_id  (int, optional) – ID of the parent category
    """
    try:
        data = request.get_json() or {}
        name = data.get('name', '').strip()
        parent_id = data.get('parent_id')

        if not name:
            return jsonify({'error': 'name is required'}), 400

        existing = Category.query.filter(db.func.lower(Category.name) == name.lower()).first()
        if existing:
            return jsonify({
                'message': 'Category already exists',
                'category': {'id': existing.id, 'name': existing.name, 'parent_id': existing.parent_id}
            }), 200

        if parent_id:
            parent = Category.query.get(int(parent_id))
            if not parent:
                return jsonify({'error': 'Parent category not found'}), 404

        cat = Category(name=name.title(), parent_id=parent_id or None)
        db.session.add(cat)
        db.session.commit()

        return jsonify({
            'message': 'Category created successfully',
            'category': {'id': cat.id, 'name': cat.name, 'parent_id': cat.parent_id}
        }), 201

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"API create_category error: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@api_bp.route('/api/categories/<int:category_id>/posts', methods=['GET'])
@api_key_required
def get_category_posts(category_id):
    """
    Get all public posts in a specific category.

    Query params:
        page     (int, default 1)
        per_page (int, default 10, max 50)
    """
    try:
        cat = Category.query.get(category_id)
        if not cat:
            return jsonify({'error': 'Category not found'}), 404

        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 10, type=int), 50)

        posts = Post.query.filter_by(category_id=category_id, is_blocked=False)\
                          .order_by(Post.date_pub.desc())\
                          .paginate(page=page, per_page=per_page, error_out=False)

        posts_data = [{
            'id': p.id,
            'title': p.title,
            'excerpt': p.desc[:150] + '...' if len(p.desc) > 150 else p.desc,
            'published_date': p.date_pub.isoformat(),
            'author': p.author.username,
            'views': p.views,
            'likes': p.like_count,
            'has_video': p.video_url is not None,
            'url': f"{request.host_url}see_more/{p.id}"
        } for p in posts.items]

        return jsonify({
            'category': {'id': cat.id, 'name': cat.name},
            'posts': posts_data,
            'total': posts.total,
            'pages': posts.pages,
            'current_page': page,
            'has_next': posts.has_next,
            'has_prev': posts.has_prev
        })

    except Exception as e:
        current_app.logger.error(f"API get_category_posts error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

