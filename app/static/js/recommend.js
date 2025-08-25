
document.addEventListener('DOMContentLoaded', function() {
    // Function to show recommended posts popup
    function showRecommendedPopup() {
        // Check if we have recommended posts data
        if (typeof recommendedPosts !== 'undefined' && recommendedPosts.length > 0) {
            const popupContent = document.getElementById('popupRecommendedPosts');
            popupContent.innerHTML = '';
            
            // Create HTML for each recommended post
            recommendedPosts.forEach(post => {
                const postHtml = `
                    <div class="col-md-6 mb-3">
                        <div class="card h-100 shadow-sm popup-post-card">
                            ${post.image_url ? `
                                <img src="{{ url_for('static', filename='images/') }}${post.image_url}" 
                                     class="card-img-top" alt="${post.title}" style="height: 180px; object-fit: cover;">
                            ` : ''}
                            <div class="card-body">
                                <h6 class="card-title">${post.title}</h6>
                                <p class="card-text small text-muted">${post.desc ? post.desc.substring(0, 100) + '...' : ''}</p>
                            </div>
                            <div class="card-footer bg-transparent">
                                <a href="/see_more/${post.id}" class="btn btn-primary btn-sm w-100">
                                    Read More <i class="fas fa-arrow-right ms-1"></i>
                                </a>
                            </div>
                        </div>
                    </div>
                `;
                popupContent.innerHTML += postHtml;
            });
            
            // Show the popup
            const popup = new bootstrap.Modal(document.getElementById('recommendedPopup'));
            popup.show();
            
            // Track that we've shown the popup in this session
            sessionStorage.setItem('popupShown', 'true');
        }
    }
    
    // Function to check if user is actively reading (scrolling or spending time)
    function checkReadingActivity() {
        let scrollTimer;
        let timeSpent = 0;
        const readingCheckInterval = setInterval(() => {
            timeSpent += 1;
            
            // Show popup after 30 seconds of reading
            if (timeSpent === 30) {
                // Check if popup was already shown in this session
                if (!sessionStorage.getItem('popupShown')) {
                    showRecommendedPopup();
                }
                clearInterval(readingCheckInterval);
            }
            
            // Also show when user reaches 70% of page height
            window.addEventListener('scroll', function() {
                clearTimeout(scrollTimer);
                scrollTimer = setTimeout(function() {
                    const scrollPercent = (window.scrollY / (document.documentElement.scrollHeight - window.innerHeight)) * 100;
                    if (scrollPercent > 70 && !sessionStorage.getItem('popupShown')) {
                        showRecommendedPopup();
                        clearInterval(readingCheckInterval);
                    }
                }, 1000);
            });
        }, 1000);
    }
    
    // Only run on article pages or after some reading time on index
    const isArticlePage = window.location.pathname.includes('/see_more/');
    const isIndexPage = window.location.pathname === '/';
    
    if (isArticlePage) {
        // Wait 5 seconds before starting to check reading activity on article pages
        setTimeout(checkReadingActivity, 5000);
    } else if (isIndexPage) {
        // On index page, show after 45 seconds or when user scrolls through several posts
        setTimeout(() => {
            if (!sessionStorage.getItem('popupShown')) {
                showRecommendedPopup();
            }
        }, 45000);
    }
});

