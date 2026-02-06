
document.addEventListener('DOMContentLoaded', function() {
    // Tab switching with AJAX loading
    const trendingTab = document.getElementById('trending-tab');
    const followingTab = document.getElementById('following-tab');
    
    // Track if tabs have been loaded
    let trendingLoaded = false;
    let followingLoaded = false;
    
    // Load trending content
    if (trendingTab) {
        trendingTab.addEventListener('shown.bs.tab', function() {
            if (!trendingLoaded) {
                loadTrendingPosts();
                trendingLoaded = true;
            }
        });
    }
    
    // Load following content
    if (followingTab) {
        followingTab.addEventListener('shown.bs.tab', function() {
            if (!followingLoaded) {
                loadFollowingPosts();
                followingLoaded = true;
            }
        });
    }
    
    function loadTrendingPosts() {
        const container = document.getElementById('trending');
        
        // Show loading
        container.innerHTML = `
            <div class="text-center py-5">
                <div class="spinner-border text-primary" role="status">
                    <span class="visually-hidden">Loading...</span>
                </div>
                <p class="text-muted mt-3">Loading trending posts...</p>
            </div>
        `;
        
        // Fetch trending posts
        fetch('/trending', {
            headers: {
                'X-Requested-With': 'XMLHttpRequest'
            }
        })
        .then(response => response.json())
        .then(data => {
            if (data.posts && data.posts.length > 0) {
                container.innerHTML = renderPosts(data.posts, 'trending');
            } else {
                container.innerHTML = `
                    <div class="empty-state text-center py-5">
                        <i class="fas fa-chart-line fa-3x text-muted mb-3"></i>
                        <h4 class="text-muted">No Trending Posts Yet</h4>
                        <p class="text-muted">Check back later for trending content</p>
                    </div>
                `;
            }
        })
        .catch(error => {
            console.error('Error loading trending posts:', error);
            container.innerHTML = `
                <div class="alert alert-danger">
                    <i class="fas fa-exclamation-triangle me-2"></i>
                    Error loading trending posts. Please try again later.
                </div>
            `;
        });
    }
    
    function loadFollowingPosts() {
        const container = document.getElementById('following');
        
        // Show loading
        container.innerHTML = `
            <div class="text-center py-5">
                <div class="spinner-border text-primary" role="status">
                    <span class="visually-hidden">Loading...</span>
                </div>
                <p class="text-muted mt-3">Loading posts from followed authors...</p>
            </div>
        `;
        
        // Fetch following posts
        fetch('/following', {
            headers: {
                'X-Requested-With': 'XMLHttpRequest'
            }
        })
        .then(response => response.json())
        .then(data => {
            if (data.posts && data.posts.length > 0) {
                container.innerHTML = renderPosts(data.posts, 'following');
            } else {
                container.innerHTML = `
                    <div class="empty-state text-center py-5">
                        <i class="fas fa-user-friends fa-3x text-muted mb-3"></i>
                        <h4 class="text-muted">No Followed Authors</h4>
                        <p class="text-muted">Start liking and commenting on posts to see content from those authors here</p>
                        <a href="#latest" class="btn btn-primary mt-3" data-bs-toggle="tab">
                            <i class="fas fa-search me-2"></i>Discover Content
                        </a>
                    </div>
                `;
            }
        })
        .catch(error => {
            console.error('Error loading following posts:', error);
            container.innerHTML = `
                <div class="alert alert-danger">
                    <i class="fas fa-exclamation-triangle me-2"></i>
                    Error loading posts. Please try again later.
                </div>
            `;
        });
    }
    
    function renderPosts(posts, type) {
        let html = '<div class="news-grid">';
        
        posts.forEach(post => {
            // Create trending badge if it's trending tab
            const trendingBadge = type === 'trending' ? 
                `<span class="badge bg-danger me-2">
                    <i class="fas fa-fire me-1"></i>Trending
                </span>` : '';
            
            const imageHtml = post.image_url ? 
                `<img src="/static/images/${post.image_url}" 
                     class="news-image w-100" alt="${post.title}" 
                     style="height: 140px; object-fit: cover;">` :
                `<div class="news-placeholder bg-light w-100 d-flex align-items-center justify-content-center" 
                     style="height: 140px;">
                    <i class="fas fa-image text-muted"></i>
                </div>`;
            
            html += `
                <div class="news-card border-bottom pb-4 mb-4">
                    <div class="row g-3">
                        <div class="col-md-4">
                            ${imageHtml}
                        </div>
                        <div class="col-md-8">
                            <div class="news-content">
                                ${trendingBadge}
                                <span class="badge bg-primary mb-2">${post.category}</span>
                                <h5 class="news-title mb-2">
                                    <a href="${post.url}" class="text-dark text-decoration-none">
                                        ${post.title}
                                    </a>
                                </h5>
                                <p class="news-excerpt text-muted mb-2">
                                    ${post.excerpt.replace(/<[^>]*>/g, '')}
                                </p>
                                <div class="news-meta d-flex align-items-center text-muted small">
                                    <div class="author-avatar me-2">
                                        <img src="https://ui-avatars.com/api/?name=${post.author}&background=random" 
                                             class="rounded-circle" width="20" height="20" alt="Author">
                                    </div>
                                    <span class="me-3">${post.author}</span>
                                    <span class="me-3"><i class="fas fa-clock me-1"></i>${post.date}</span>
                                    <span class="me-3"><i class="fas fa-eye me-1"></i>${post.views}</span>
                                    <span class="me-3"><i class="fas fa-heart me-1"></i>${post.likes}</span>
                                    <span><i class="fas fa-comment me-1"></i>${post.comments}</span>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            `;
        });
        
        html += '</div>';
        return html;
    }
});

