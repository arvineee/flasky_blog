// Like Button Functionality
document.addEventListener('DOMContentLoaded', function() {
    console.log('Like script loaded');
    
    // Get CSRF token
    function getCSRFToken() {
        const metaToken = document.querySelector('meta[name="csrf-token"]');
        if (metaToken) {
            return metaToken.getAttribute('content');
        }
        const inputToken = document.querySelector('input[name="csrf_token"]');
        if (inputToken) {
            return inputToken.value;
        }
        return '';
    }

    // Handle like button clicks
    const likeButtons = document.querySelectorAll('.like-btn, .btn-like');
    
    likeButtons.forEach(button => {
        button.addEventListener('click', function(e) {
            e.preventDefault();
            e.stopPropagation();
            
            const postId = this.getAttribute('data-post-id');
            const likeIcon = this.querySelector('i');
            const likeCount = this.querySelector('.like-count');
            
            if (!postId) {
                console.error('No post ID found');
                return;
            }
            
            // Disable button during request
            button.disabled = true;
            
            // Send like request
            fetch(`/like_post/${postId}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest',
                    'X-CSRFToken': getCSRFToken()
                },
                credentials: 'same-origin'
            })
            .then(response => {
                if (!response.ok) {
                    if (response.status === 401) {
                        throw new Error('Please log in to like posts');
                    }
                    throw new Error('Network response was not ok');
                }
                return response.json();
            })
            .then(data => {
                if (data.status === 'success') {
                    // Update like count
                    if (likeCount) {
                        likeCount.textContent = data.like_count;
                    }
                    
                    // Update icon based on action
                    if (likeIcon) {
                        if (data.action === 'liked') {
                            likeIcon.classList.remove('far');
                            likeIcon.classList.add('fas', 'text-danger');
                            button.classList.add('liked');
                        } else {
                            likeIcon.classList.remove('fas', 'text-danger');
                            likeIcon.classList.add('far');
                            button.classList.remove('liked');
                        }
                    }
                    
                    // Add animation
                    button.classList.add('animate-like');
                    setTimeout(() => {
                        button.classList.remove('animate-like');
                    }, 300);
                } else {
                    throw new Error(data.message || 'Failed to like post');
                }
            })
            .catch(error => {
                console.error('Error:', error);
                // Show error message
                showNotification(error.message || 'Failed to like post. Please try again.', 'error');
            })
            .finally(() => {
                // Re-enable button
                button.disabled = false;
            });
        });
    });
    
    // Check if user has already liked posts on page load
    checkLikedPosts();
});

// Check which posts the current user has liked
function checkLikedPosts() {
    const likeButtons = document.querySelectorAll('.like-btn, .btn-like');
    const postIds = Array.from(likeButtons).map(btn => btn.getAttribute('data-post-id')).filter(id => id);
    
    if (postIds.length === 0) return;
    
    // Send request to check liked posts
    fetch('/check_liked_posts', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest',
            'X-CSRFToken': getCSRFToken()
        },
        body: JSON.stringify({ post_ids: postIds }),
        credentials: 'same-origin'
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            data.liked_posts.forEach(postId => {
                const button = document.querySelector(`.like-btn[data-post-id="${postId}"], .btn-like[data-post-id="${postId}"]`);
                if (button) {
                    const icon = button.querySelector('i');
                    if (icon) {
                        icon.classList.remove('far');
                        icon.classList.add('fas', 'text-danger');
                    }
                    button.classList.add('liked');
                }
            });
        }
    })
    .catch(error => {
        console.error('Error checking liked posts:', error);
    });
}

// Get CSRF token helper
function getCSRFToken() {
    const metaToken = document.querySelector('meta[name="csrf-token"]');
    if (metaToken) {
        return metaToken.getAttribute('content');
    }
    const inputToken = document.querySelector('input[name="csrf_token"]');
    if (inputToken) {
        return inputToken.value;
    }
    return '';
}

// Show notification helper
function showNotification(message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `alert alert-${type === 'error' ? 'danger' : 'success'} alert-dismissible fade show position-fixed`;
    notification.style.cssText = 'top: 20px; right: 20px; z-index: 9999; min-width: 300px;';
    notification.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    document.body.appendChild(notification);
    
    // Auto remove after 3 seconds
    setTimeout(() => {
        notification.remove();
    }, 3000);
}
