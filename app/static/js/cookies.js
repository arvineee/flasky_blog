<script>
// Cookie functions
function setCookie(name, value, days) {
    const expires = new Date();
    expires.setTime(expires.getTime() + (days * 24 * 60 * 60 * 1000));
    document.cookie = `${name}=${value};expires=${expires.toUTCString()};path=/`;
}

function getCookie(name) {
    const nameEQ = `${name}=`;
    const ca = document.cookie.split(';');
    for(let i = 0; i < ca.length; i++) {
        let c = ca[i];
        while (c.charAt(0) === ' ') c = c.substring(1, c.length);
        if (c.indexOf(nameEQ) === 0) return c.substring(nameEQ.length, c.length);
    }
    return null;
}

// Newsletter modal handling with cookies
document.addEventListener('DOMContentLoaded', function() {
    // Check if newsletter modal was shown recently (within 7 days)
    const newsletterShown = getCookie('newsletterShown');
    
    if (!newsletterShown) {
        // Show newsletter modal after 30 seconds
        setTimeout(function() {
            var newsletterModal = new bootstrap.Modal(document.getElementById('newsletterModal'));
            newsletterModal.show();
            
            // Set cookie to remember that newsletter was shown
            setCookie('newsletterShown', 'true', 7); // Remember for 7 days
            
            // When modal is closed, set focus back to page
            document.getElementById('newsletterModal').addEventListener('hidden.bs.modal', function () {
                document.body.style.overflow = 'auto';
            });
        }, 30000);
    }
    
    // Initialize featured posts carousel
    var featuredCarousel = document.getElementById('featuredCarousel');
    if (featuredCarousel) {
        var carousel = new bootstrap.Carousel(featuredCarousel, {
            interval: 5000,
            wrap: true
        });
    }
    
    // Filter tabs functionality
    const filterTabs = document.querySelectorAll('[data-bs-toggle="tab"]');
    
    filterTabs.forEach(tab => {
        tab.addEventListener('shown.bs.tab', function(event) {
            const target = event.target.getAttribute('data-bs-target');
            // Update URL with active tab
            const url = new URL(window.location);
            url.searchParams.set('tab', target.replace('#', ''));
            window.history.replaceState({}, '', url);
        });
    });
    
    // Handle tab parameter from URL
    const urlParams = new URLSearchParams(window.location.search);
    const tabParam = urlParams.get('tab');
    if (tabParam) {
        const tabElement = document.querySelector(`[data-bs-target="#${tabParam}"]`);
        if (tabElement) {
            new bootstrap.Tab(tabElement).show();
        }
    }
    
    // Like functionality
    const likeButtons = document.querySelectorAll('.like-btn');
    likeButtons.forEach(button => {
        button.addEventListener('click', function() {
            const postId = this.getAttribute('data-post-id');
            // Your like functionality here
        });
    });
});

// Handle newsletter form submission
function handleNewsletterSubmit(event) {
    event.preventDefault();
    const formData = new FormData(event.target);
    const email = formData.get('email');
    
    fetch("{{ url_for('newsletter.subscribe') }}", {
        method: 'POST',
        body: formData,
        headers: {
            'X-Requested-With': 'XMLHttpRequest'
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            // Show success message
            alert('Successfully subscribed to newsletter!');
            // Hide modal
            var modal = bootstrap.Modal.getInstance(document.getElementById('newsletterModal'));
            modal.hide();
        } else {
            alert('Error: ' + data.message);
        }
    })
    .catch(error => {
        console.error('Error:', error);
        alert('An error occurred. Please try again.');
    });
    
    return false;
}
</script>
