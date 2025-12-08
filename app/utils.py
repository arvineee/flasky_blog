import os
import logging
import hashlib
import re
import random
from datetime import datetime
from PIL import Image, ImageDraw, ImageFont
from flask import url_for, current_app
import bleach
# Combined imports for models
from app.models import Post, User, AdContent

logger = logging.getLogger(__name__)

# ==========================================
# File & Image Utilities
# ==========================================

def allowed_file(filename, extensions=None):
    """
    Check if file extension is allowed
    """
    if extensions is None:
        extensions = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
    
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
    try:
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
    except Exception as e:
        logger.error(f"Error getting recommended posts: {str(e)}")
        return []


def add_watermark_to_image(image_path, watermark_text="Arval-Blog"):
    """
    Add watermark to an image
    """
    try:
        # Open the image
        image = Image.open(image_path).convert("RGBA")
        
        # Create a transparent layer for watermark
        watermark = Image.new("RGBA", image.size, (255, 255, 255, 0))
        
        # Create drawing context
        draw = ImageDraw.Draw(watermark)
        
        # Try to load a font, fallback to default if not available
        try:
            # Try different font paths
            font_paths = [
                "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
                "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
                os.path.join(os.path.dirname(__file__), "fonts", "Arial.ttf")
            ]
            
            # Dynamic font size based on image dimensions
            font_size = max(24, int(min(image.size) * 0.03))
            font = None
            
            for font_path in font_paths:
                if os.path.exists(font_path):
                    font = ImageFont.truetype(font_path, font_size)
                    break
            
            if font is None:
                font = ImageFont.load_default()
        except Exception as font_error:
            logger.warning(f"Could not load custom font: {font_error}")
            font = ImageFont.load_default()
        
        # Calculate text size and position
        temp_draw = ImageDraw.Draw(Image.new("RGB", (1, 1)))
        bbox = temp_draw.textbbox((0, 0), watermark_text, font=font)
        text_width = bbox[2] - bbox[0]
        text_height = bbox[3] - bbox[1]
        
        # Position watermark at bottom right with padding
        margin = 20
        position = (
            image.width - text_width - margin,
            image.height - text_height - margin
        )
        
        # Add text with shadow effect for better visibility
        # Shadow
        draw.text(
            (position[0] + 2, position[1] + 2),
            watermark_text,
            font=font,
            fill=(0, 0, 0, 180)
        )
        # Main text
        draw.text(
            position,
            watermark_text,
            font=font,
            fill=(255, 255, 255, 200)
        )
        
        # Combine original image with watermark
        watermarked = Image.alpha_composite(image, watermark)
        
        # Convert back to RGB if saving as JPEG
        if image_path.lower().endswith(('.jpg', '.jpeg')):
            watermarked = watermarked.convert("RGB")
        
        # Save the watermarked image
        watermarked.save(image_path, quality=95)
        
        logger.info(f"Watermark added to {image_path}")
        return True
        
    except Exception as e:
        logger.error(f"Error adding watermark to {image_path}: {str(e)}")
        return False


def process_uploaded_image(file, upload_folder, filename):
    """
    Save uploaded image and add watermark
    """
    try:
        # Ensure upload folder exists
        os.makedirs(upload_folder, exist_ok=True)
        
        # Save the file
        file_path = os.path.join(upload_folder, filename)
        file.save(file_path)
        
        # Add watermark
        if add_watermark_to_image(file_path):
            logger.info(f"Image processed and watermarked: {filename}")
        else:
            logger.warning(f"Watermark failed but image saved: {filename}")
        
        return file_path
        
    except Exception as e:
        logger.error(f"Error processing image: {str(e)}")
        raise

# ==========================================
# Ad Management Utilities
# ==========================================

def get_random_inline_ad():
    """Get a random active inline ad"""
    try:
        inline_ads = AdContent.query.filter(
            AdContent.is_active == True,
            AdContent.placement == 'inline',
            (AdContent.end_date == None) | (AdContent.end_date >= datetime.utcnow())
        ).all()
        
        if inline_ads:
            ad = random.choice(inline_ads)
            ad.impressions += 1
            from app import db
            db.session.commit()
            return ad
        return None
    except Exception as e:
        logger.error(f"Error getting random inline ad: {str(e)}")
        return None


def insert_inline_ads_automatically(content, num_ads=1):
    """
    Automatically insert inline ads into content at natural breaks
    """
    try:
        # Split content by paragraphs
        paragraphs = re.split(r'(</p>|</div>)', content)
        new_content_parts = []
        ad_inserted_count = 0
        
        for i, paragraph in enumerate(paragraphs):
            new_content_parts.append(paragraph)
            
            # Insert ad after every 3-5 paragraphs
            if (i + 1) % random.randint(3, 5) == 0 and ad_inserted_count < num_ads:
                ad = get_random_inline_ad()
                if ad:
                    ad_html = f'''
                    <div class="inline-ad-auto my-4 p-3 border rounded bg-light position-relative">
                        <span class="badge bg-info position-absolute top-0 start-0 m-2">Advertisement</span>
                        <div class="ad-content">
                            {ad.content}
                        </div>
                        <div class="text-end mt-2">
                            <a href="{url_for('main.track_ad_click', ad_id=ad.id)}" 
                               target="_blank" 
                               class="btn btn-sm btn-outline-primary">
                                Learn More
                            </a>
                        </div>
                    </div>
                    '''
                    new_content_parts.append(ad_html)
                    ad_inserted_count += 1
        
        # Join all parts
        return ''.join(new_content_parts)
        
    except Exception as e:
        logger.error(f"Error inserting inline ads automatically: {str(e)}")
        return content


def process_ad_shortcodes(content):
    """
    Process ad shortcodes in content
    Returns: (processed_content, ad_ids_found)
    """
    try:
        from app import db
        
        ad_ids_found = []
        
        def replace_shortcode(match):
            ad_id = int(match.group(1))
            ad_ids_found.append(ad_id)
            
            try:
                ad = AdContent.query.filter(
                    AdContent.id == ad_id,
                    AdContent.is_active == True,
                    (AdContent.end_date == None) | (AdContent.end_date >= datetime.utcnow())
                ).first()
                
                if ad:
                    # Update impressions
                    ad.impressions += 1
                    db.session.commit()
                    
                    # Generate ad HTML based on placement
                    if ad.placement == 'inline':
                        return f'''
                        <div class="inline-ad-shortcode my-4 p-3 border rounded bg-light position-relative">
                            <span class="badge bg-warning position-absolute top-0 start-0 m-2">Sponsored</span>
                            <div class="ad-content">
                                {ad.content}
                            </div>
                            <div class="text-end mt-2">
                                <a href="{{ url_for('main.track_ad_click', ad_id={ad.id}) }}" 
                                   target="_blank" 
                                   class="btn btn-sm btn-outline-primary">
                                    Visit Site
                                </a>
                            </div>
                        </div>
                        '''
                    else:
                        return ad.content
                        
            except Exception as e:
                logger.error(f"Error processing ad shortcode {ad_id}: {str(e)}")
            
            return ''  # Return empty if ad not found
        
        # Process [ad id=X] shortcodes
        pattern = r'\[ad id=(\d+)\]'
        processed_content = re.sub(pattern, replace_shortcode, content)
        
        return processed_content, ad_ids_found
        
    except Exception as e:
        logger.error(f"Error processing ad shortcodes: {str(e)}")
        return content, []


def get_ad_stats():
    """Get comprehensive ad statistics"""
    try:
        from app.models import AdContent
        from app import db
        
        total_ads = AdContent.query.count()
        active_ads = AdContent.query.filter_by(is_active=True).count()
        total_clicks = db.session.query(db.func.sum(AdContent.clicks)).scalar() or 0
        total_impressions = db.session.query(db.func.sum(AdContent.impressions)).scalar() or 0
        total_revenue = db.session.query(db.func.sum(AdContent.price)).scalar() or 0
        
        # Placement stats
        placement_stats = {}
        placements = ['sidebar', 'header', 'inline', 'footer']
        for placement in placements:
            placement_ads = AdContent.query.filter_by(placement=placement).count()
            placement_clicks = db.session.query(db.func.sum(AdContent.clicks)).filter_by(placement=placement).scalar() or 0
            placement_impressions = db.session.query(db.func.sum(AdContent.impressions)).filter_by(placement=placement).scalar() or 0
            
            placement_stats[placement] = {
                'count': placement_ads,
                'clicks': placement_clicks,
                'impressions': placement_impressions,
                'ctr': (placement_clicks / placement_impressions * 100) if placement_impressions > 0 else 0
            }
        
        return {
            'total_ads': total_ads,
            'active_ads': active_ads,
            'total_clicks': total_clicks,
            'total_impressions': total_impressions,
            'total_revenue': total_revenue,
            'overall_ctr': (total_clicks / total_impressions * 100) if total_impressions > 0 else 0,
            'placement_stats': placement_stats
        }
        
    except Exception as e:
        logger.error(f"Error getting ad stats: {str(e)}")
        return {}

