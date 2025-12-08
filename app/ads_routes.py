from flask import Blueprint, render_template, jsonify, request, redirect, url_for, flash
from flask_login import login_required, current_user
from app.models import AdContent
from app import db
from datetime import datetime
import logging

ads_bp = Blueprint('ads', __name__)
logger = logging.getLogger(__name__)

@ads_bp.route('/ads/stats')
@login_required
def ad_stats():
    """Display detailed ad statistics"""
    if not current_user.is_admin:
        flash("Access denied", "danger")
        return redirect(url_for('main.index'))
    
    from app.utils import get_ad_stats
    stats_dict = get_ad_stats()  # This returns a dictionary
    
    # Get recent ads
    recent_ads = AdContent.query.order_by(AdContent.created_at.desc()).limit(10).all()
    
    # Get top performing ads
    top_ads = AdContent.query.order_by(AdContent.clicks.desc()).limit(5).all()
    
    # Calculate insights for template
    best_placement = None
    best_ctr = 0
    most_views = None
    max_impressions = 0
    revenue_gen = None
    max_revenue = 0
    
    # Make sure placement_stats exists in the dictionary
    if 'placement_stats' in stats_dict and stats_dict['placement_stats']:
        for placement, data in stats_dict['placement_stats'].items():
            # Best CTR
            if data.get('ctr', 0) > best_ctr:
                best_placement = placement
                best_ctr = data.get('ctr', 0)
                
            # Most impressions
            if data.get('impressions', 0) > max_impressions:
                most_views = placement
                max_impressions = data.get('impressions', 0)
                
            # Most revenue
            total_ads = stats_dict.get('total_ads', 1)
            total_revenue = stats_dict.get('total_revenue', 0)
            count = data.get('count', 0)
            placement_revenue = total_revenue * (count / total_ads if total_ads > 0 else 0)
            if placement_revenue > max_revenue:
                revenue_gen = placement
                max_revenue = placement_revenue
    
    return render_template('ad_stats.html',
                         stats=stats_dict,  # Pass dictionary, not object
                         recent_ads=recent_ads,
                         top_ads=top_ads,
                         best_placement=best_placement,
                         best_ctr=best_ctr,
                         most_views=most_views,
                         revenue_gen=revenue_gen)

@ads_bp.route('/ads/zone/<placement>')
def ad_zone(placement):
    """Serve ads for a specific zone (AJAX endpoint)"""
    try:
        ads = AdContent.query.filter(
            AdContent.placement == placement,
            AdContent.is_active == True,
            (AdContent.end_date == None) | (AdContent.end_date >= datetime.utcnow())
        ).order_by(AdContent.created_at.desc()).limit(3).all()
        
        ads_data = []
        for ad in ads:
            ad.impressions += 1
            ads_data.append({
                'id': ad.id,
                'title': ad.title,
                'content': ad.content,
                'advertiser': ad.advertiser_name,
                'clicks': ad.clicks,
                'impressions': ad.impressions
            })
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'ads': ads_data,
            'placement': placement
        })
        
    except Exception as e:
        logger.error(f"Error serving ads for zone {placement}: {str(e)}")
        return jsonify({'success': False, 'message': str(e)})

@ads_bp.route('/ads/preview/<int:ad_id>')
@login_required
def preview_ad(ad_id):
    """Preview an ad"""
    if not current_user.is_admin:
        flash("Access denied", "danger")
        return redirect(url_for('main.index'))
    
    ad = AdContent.query.get_or_404(ad_id)
    
    return render_template('ad_preview.html', ad=ad)

@ads_bp.route('/ads/rotate')
def rotate_ads():
    """Rotate ads (for AJAX loading)"""
    placement = request.args.get('placement', 'sidebar')
    limit = request.args.get('limit', 3, type=int)
    
    try:
        ads = AdContent.query.filter(
            AdContent.placement == placement,
            AdContent.is_active == True,
            (AdContent.end_date == None) | (AdContent.end_date >= datetime.utcnow())
        ).order_by(db.func.random()).limit(limit).all()
        
        ads_html = []
        for ad in ads:
            ad.impressions += 1
            ads_html.append(f'''
            <div class="rotating-ad mb-3 p-3 border rounded">
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
            ''')
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'html': ''.join(ads_html)
        })
        
    except Exception as e:
        logger.error(f"Error rotating ads: {str(e)}")
        return jsonify({'success': False, 'message': str(e)})

@ads_bp.route('/ads/analytics')
@login_required
def ad_analytics():
    """Advanced ad analytics dashboard"""
    if not current_user.is_admin:
        flash("Access denied", "danger")
        return redirect(url_for('main.index'))
    
    # Get date range from request
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    
    # Build query
    query = AdContent.query
    
    if start_date:
        query = query.filter(AdContent.created_at >= datetime.strptime(start_date, '%Y-%m-%d'))
    if end_date:
        query = query.filter(AdContent.created_at <= datetime.strptime(end_date, '%Y-%m-%d'))
    
    all_ads = query.order_by(AdContent.created_at.desc()).all()
    
    # Calculate metrics
    total_spent = sum(ad.price or 0 for ad in all_ads)
    total_clicks = sum(ad.clicks for ad in all_ads)
    total_impressions = sum(ad.impressions for ad in all_ads)
    
    # Placement breakdown
    placements = {}
    for ad in all_ads:
        if ad.placement not in placements:
            placements[ad.placement] = {
                'count': 0,
                'clicks': 0,
                'impressions': 0,
                'revenue': 0
            }
        placements[ad.placement]['count'] += 1
        placements[ad.placement]['clicks'] += ad.clicks
        placements[ad.placement]['impressions'] += ad.impressions
        placements[ad.placement]['revenue'] += (ad.price or 0)
    
    # Calculate CTR for each placement
    for placement in placements.values():
        placement['ctr'] = (placement['clicks'] / placement['impressions'] * 100) if placement['impressions'] > 0 else 0
    
    return render_template('ad_analytics.html',
                         all_ads=all_ads,
                         total_spent=total_spent,
                         total_clicks=total_clicks,
                         total_impressions=total_impressions,
                         placements=placements,
                         start_date=start_date,
                         end_date=end_date)
