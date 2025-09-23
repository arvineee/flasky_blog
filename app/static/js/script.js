document.addEventListener("DOMContentLoaded", () => {
    // Video player functionality
    const videos = document.querySelectorAll(".custom-video");

    videos.forEach((video, index) => {
        const videoWrapper = video.closest(".video-wrapper");
        const playOverlay = videoWrapper.querySelector(".play-overlay");
        const bigPlayButton = videoWrapper.querySelector(".big-play-button");

        // Pause all other videos when a video starts
        const pauseAllVideos = () => {
            videos.forEach((vid) => {
                if (vid !== video) {
                    vid.pause();
                    vid.closest(".video-wrapper").querySelector(".play-overlay").style.display = "flex";
                }
            });
        };

        // Play video on button click
        bigPlayButton.addEventListener("click", () => {
            video.play();
            playOverlay.style.display = "none";
        });

        // Show overlay when paused
        video.addEventListener("pause", () => {
            playOverlay.style.display = "flex";
        });

        // Hide overlay when playing
        video.addEventListener("play", () => {
            pauseAllVideos();
            playOverlay.style.display = "none";
        });

        // Auto-scroll and play next video
        video.addEventListener("ended", () => {
            const nextVideo = videos[index + 1];
            if (nextVideo) {
                nextVideo.scrollIntoView({ behavior: "smooth" });
                setTimeout(() => nextVideo.play(), 1000);
            }
        });

        // Pause video when out of viewport
        const observer = new IntersectionObserver((entries) => {
            entries.forEach((entry) => {
                if (!entry.isIntersecting) {
                    video.pause();
                }
            });
        }, { threshold: 0.5 });

        observer.observe(video);
    });

    // User Management functionality
    const userManagementCollapse = document.getElementById('userManagementCollapse');
    
    if (userManagementCollapse) {
        const collapseButton = document.querySelector('[data-bs-target="#userManagementCollapse"]');
        
        // Load saved state from localStorage
        const savedState = localStorage.getItem('userManagementCollapse');
        if (savedState === 'false') {
            const bsCollapse = new bootstrap.Collapse(userManagementCollapse, {
                toggle: false
            });
            bsCollapse.hide();
            if (collapseButton) {
                collapseButton.querySelector('i').classList.remove('fa-chevron-down');
                collapseButton.querySelector('i').classList.add('fa-chevron-right');
            }
        }
        
        // Handle collapse events
        userManagementCollapse.addEventListener('show.bs.collapse', function() {
            if (collapseButton) {
                collapseButton.querySelector('i').classList.remove('fa-chevron-right');
                collapseButton.querySelector('i').classList.add('fa-chevron-down');
            }
            localStorage.setItem('userManagementCollapse', 'true');
        });
        
        userManagementCollapse.addEventListener('hide.bs.collapse', function() {
            if (collapseButton) {
                collapseButton.querySelector('i').classList.remove('fa-chevron-down');
                collapseButton.querySelector('i').classList.add('fa-chevron-right');
            }
            localStorage.setItem('userManagementCollapse', 'false');
        });
    }

    // Enhanced search functionality
    const searchForm = document.querySelector('form[action*="admin_dashboard"]');
    if (searchForm) {
        const searchInput = searchForm.querySelector('input[name="q"]');
        
        // Debounce search to avoid too many requests
        let debounceTimer;
        if (searchInput) {
            searchInput.addEventListener('input', function() {
                clearTimeout(debounceTimer);
                debounceTimer = setTimeout(() => {
                    if (this.value.length > 2 || this.value.length === 0) {
                        searchForm.submit();
                    }
                }, 500);
            });
        }
    }

    // CSRF Token handling for all forms
    function getCSRFToken() {
        // Try to get CSRF token from meta tag
        const metaToken = document.querySelector('meta[name="csrf-token"]');
        if (metaToken) {
            return metaToken.getAttribute('content');
        }
        
        // Try to get CSRF token from hidden input
        const inputToken = document.querySelector('input[name="csrf_token"]');
        if (inputToken) {
            return inputToken.value;
        }
        
        // Try to get CSRF token from Flask's built-in template variable
        if (typeof csrf_token !== 'undefined') {
            return csrf_token;
        }
        
        console.error('CSRF token not found');
        return '';
    }

    // Add CSRF token to all forms that don't have it
    document.querySelectorAll('form').forEach(form => {
        if (!form.querySelector('input[name="csrf_token"]')) {
            const csrfInput = document.createElement('input');
            csrfInput.type = 'hidden';
            csrfInput.name = 'csrf_token';
            csrfInput.value = getCSRFToken();
            form.appendChild(csrfInput);
        }
    });

    // Confirm actions for destructive operations with proper CSRF handling
    document.querySelectorAll('form[action*="/ban"], form[action*="/unban"], form[action*="/promote"], form[action*="/demote"]').forEach(form => {
        form.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const action = this.getAttribute('action');
            let message = 'Are you sure you want to perform this action?';
            
            if (action.includes('ban')) {
                message = 'Are you sure you want to ban this user?';
            } else if (action.includes('unban')) {
                message = 'Are you sure you want to unban this user?';
            } else if (action.includes('promote')) {
                message = 'Are you sure you want to promote this user to admin?';
            } else if (action.includes('demote')) {
                message = 'Are you sure you want to demote this admin to regular user?';
            }
            
            if (confirm(message)) {
                // Ensure CSRF token is present
                let csrfInput = this.querySelector('input[name="csrf_token"]');
                if (!csrfInput) {
                    csrfInput = document.createElement('input');
                    csrfInput.type = 'hidden';
                    csrfInput.name = 'csrf_token';
                    csrfInput.value = getCSRFToken();
                    this.appendChild(csrfInput);
                }
                
                // Submit the form
                this.submit();
            }
        });
    });

    // AJAX CSRF setup
    if (typeof jQuery !== 'undefined') {
        $.ajaxSetup({
            beforeSend: function(xhr, settings) {
                if (!/^(GET|HEAD|OPTIONS|TRACE)$/i.test(settings.type) && !this.crossDomain) {
                    xhr.setRequestHeader("X-CSRFToken", getCSRFToken());
                }
            }
        });
    }
});
