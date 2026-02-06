// AJAX COMMENTS SYSTEM - FRONTEND
// Save as: static/js/ajax-comments.js

/**
 * Real-time comment system with AJAX
 * Features: Add, edit, delete, flag comments without page reload
 */

class CommentSystem {
    constructor(postId) {
        this.postId = postId;
        this.isAdmin = document.body.dataset.isAdmin === 'true';
        this.currentUserId = parseInt(document.body.dataset.userId) || null;
        this.csrf_token = document.querySelector('meta[name="csrf-token"]')?.content || '';
        
        this.init();
    }
    
    init() {
        this.setupEventListeners();
        this.loadComments();
    }
    
    setupEventListeners() {
        // Submit comment form
        const commentForm = document.getElementById('commentForm');
        if (commentForm) {
            commentForm.addEventListener('submit', (e) => this.handleSubmit(e));
        }
        
        // Character counter
        const textarea = document.getElementById('commentTextarea');
        if (textarea) {
            textarea.addEventListener('input', (e) => this.updateCharCount(e.target));
        }
    }
    
    async handleSubmit(e) {
        e.preventDefault();
        
        const textarea = document.getElementById('commentTextarea');
        const submitBtn = document.getElementById('commentSubmitBtn');
        const content = textarea.value.trim();
        
        if (!content) {
            this.showToast('Please enter a comment', 'warning');
            return;
        }
        
        if (content.length > 1000) {
            this.showToast('Comment too long (max 1000 characters)', 'warning');
            return;
        }
        
        // Disable form
        submitBtn.disabled = true;
        submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Posting...';
        
        try {
            const response = await fetch(`/api/comment/add/${this.postId}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': this.csrf_token
                },
                body: JSON.stringify({ content })
            });
            
            const data = await response.json();
            
            if (data.success) {
                // Clear form
                textarea.value = '';
                this.updateCharCount(textarea);
                
                // Add comment to list
                this.addCommentToDOM(data.comment, true);
                
                // Update comment count
                this.updateCommentCount(data.comment_count);
                
                // Show success
                this.showToast('Comment posted successfully!', 'success');
                
                // Scroll to new comment
                document.getElementById(`comment-${data.comment.id}`)?.scrollIntoView({
                    behavior: 'smooth',
                    block: 'center'
                });
            } else {
                this.showToast(data.message || 'Error posting comment', 'danger');
            }
        } catch (error) {
            console.error('Error posting comment:', error);
            this.showToast('Network error. Please try again.', 'danger');
        } finally {
            // Re-enable form
            submitBtn.disabled = false;
            submitBtn.innerHTML = '<i class="fas fa-paper-plane me-1"></i>Post Comment';
        }
    }
    
    async loadComments(page = 1) {
        const commentsList = document.getElementById('commentsList');
        
        if (!commentsList) return;
        
        // Show loading
        if (page === 1) {
            commentsList.innerHTML = `
                <div class="text-center py-5">
                    <div class="spinner-border text-primary" role="status">
                        <span class="visually-hidden">Loading comments...</span>
                    </div>
                    <p class="mt-2 text-muted">Loading comments...</p>
                </div>
            `;
        }
        
        try {
            const response = await fetch(`/api/comments/${this.postId}?page=${page}`);
            const data = await response.json();
            
            if (data.success) {
                if (data.comments.length === 0 && page === 1) {
                    commentsList.innerHTML = `
                        <div class="text-center text-muted py-5">
                            <i class="fas fa-comments fa-3x mb-3 opacity-50"></i>
                            <p>No comments yet. Be the first to comment!</p>
                        </div>
                    `;
                } else {
                    if (page === 1) {
                        commentsList.innerHTML = '';
                    }
                    
                    data.comments.forEach(comment => {
                        this.addCommentToDOM(comment, false);
                    });
                    
                    // Add load more button if needed
                    if (data.has_next) {
                        this.addLoadMoreButton(page + 1);
                    }
                }
            }
        } catch (error) {
            console.error('Error loading comments:', error);
            commentsList.innerHTML = `
                <div class="alert alert-danger">
                    <i class="fas fa-exclamation-triangle me-2"></i>
                    Error loading comments. Please refresh the page.
                </div>
            `;
        }
    }
    
    addCommentToDOM(comment, prepend = false) {
        const commentsList = document.getElementById('commentsList');
        if (!commentsList) return;
        
        const commentHTML = this.createCommentHTML(comment);
        
        if (prepend) {
            commentsList.insertAdjacentHTML('afterbegin', commentHTML);
        } else {
            commentsList.insertAdjacentHTML('beforeend', commentHTML);
        }
        
        // Add event listeners to new comment
        this.attachCommentListeners(comment.id);
        
        // Highlight new comment
        if (prepend) {
            const commentEl = document.getElementById(`comment-${comment.id}`);
            commentEl.classList.add('comment-new');
            setTimeout(() => commentEl.classList.remove('comment-new'), 2000);
        }
    }
    
    createCommentHTML(comment) {
        const isOwner = this.currentUserId === comment.user.id;
        const canModerate = this.isAdmin;
        const showModeration = canModerate && comment.is_flagged;
        const isHidden = comment.is_hidden;
        
        return `
            <div class="comment ${isHidden ? 'comment-hidden' : ''} ${showModeration ? 'comment-flagged' : ''}" 
                 id="comment-${comment.id}" 
                 data-comment-id="${comment.id}">
                <div class="d-flex gap-3">
                    <img src="${comment.user.avatar_url}" 
                         alt="${comment.user.username}" 
                         class="rounded-circle comment-avatar" 
                         style="width: 40px; height: 40px;">
                    <div class="flex-grow-1">
                        <div class="d-flex justify-content-between align-items-start">
                            <div>
                                <h6 class="mb-0">
                                    ${comment.user.username}
                                    ${comment.edited ? '<small class="text-muted ms-2">(edited)</small>' : ''}
                                </h6>
                                <small class="text-muted">${comment.date_posted}</small>
                            </div>
                            <div class="dropdown">
                                <button class="btn btn-sm btn-link text-secondary" 
                                        type="button" 
                                        data-bs-toggle="dropdown">
                                    <i class="fas fa-ellipsis-v"></i>
                                </button>
                                <ul class="dropdown-menu dropdown-menu-end">
                                    ${isOwner ? `
                                        <li>
                                            <button class="dropdown-item edit-comment" data-comment-id="${comment.id}">
                                                <i class="fas fa-edit me-2"></i>Edit
                                            </button>
                                        </li>
                                    ` : ''}
                                    ${isOwner || canModerate ? `
                                        <li>
                                            <button class="dropdown-item text-danger delete-comment" data-comment-id="${comment.id}">
                                                <i class="fas fa-trash me-2"></i>Delete
                                            </button>
                                        </li>
                                    ` : ''}
                                    ${canModerate ? `
                                        <li><hr class="dropdown-divider"></li>
                                        <li>
                                            <button class="dropdown-item ${comment.is_flagged ? 'text-success' : 'text-warning'} flag-comment" 
                                                    data-comment-id="${comment.id}"
                                                    data-action="${comment.is_flagged ? 'unflag' : 'flag'}">
                                                <i class="fas fa-flag me-2"></i>${comment.is_flagged ? 'Unflag' : 'Flag'}
                                            </button>
                                        </li>
                                        <li>
                                            <button class="dropdown-item hide-comment" 
                                                    data-comment-id="${comment.id}"
                                                    data-action="${comment.is_hidden ? 'unhide' : 'hide'}">
                                                <i class="fas fa-eye-slash me-2"></i>${comment.is_hidden ? 'Unhide' : 'Hide'}
                                            </button>
                                        </li>
                                    ` : ''}
                                </ul>
                            </div>
                        </div>
                        
                        ${showModeration ? `
                            <div class="alert alert-warning alert-sm mt-2 mb-2">
                                <i class="fas fa-flag me-2"></i>
                                <strong>Flagged:</strong> ${comment.flag_reason}
                            </div>
                        ` : ''}
                        
                        ${isHidden && canModerate ? `
                            <div class="alert alert-danger alert-sm mt-2 mb-2">
                                <i class="fas fa-eye-slash me-2"></i>
                                <strong>Hidden from users</strong>
                            </div>
                        ` : ''}
                        
                        <div class="comment-content mt-2" id="comment-content-${comment.id}">
                            <p class="mb-0">${this.escapeHtml(comment.content)}</p>
                        </div>
                        
                        <div class="comment-edit-form d-none mt-2" id="comment-edit-${comment.id}">
                            <textarea class="form-control mb-2" rows="3">${this.escapeHtml(comment.content)}</textarea>
                            <div>
                                <button class="btn btn-sm btn-primary save-edit" data-comment-id="${comment.id}">
                                    <i class="fas fa-check me-1"></i>Save
                                </button>
                                <button class="btn btn-sm btn-secondary cancel-edit" data-comment-id="${comment.id}">
                                    Cancel
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }
    
    attachCommentListeners(commentId) {
        const comment = document.getElementById(`comment-${commentId}`);
        if (!comment) return;
        
        // Edit button
        const editBtn = comment.querySelector('.edit-comment');
        if (editBtn) {
            editBtn.addEventListener('click', () => this.editComment(commentId));
        }
        
        // Delete button
        const deleteBtn = comment.querySelector('.delete-comment');
        if (deleteBtn) {
            deleteBtn.addEventListener('click', () => this.deleteComment(commentId));
        }
        
        // Flag button
        const flagBtn = comment.querySelector('.flag-comment');
        if (flagBtn) {
            flagBtn.addEventListener('click', (e) => {
                const action = e.target.closest('button').dataset.action;
                this.flagComment(commentId, action);
            });
        }
        
        // Hide button
        const hideBtn = comment.querySelector('.hide-comment');
        if (hideBtn) {
            hideBtn.addEventListener('click', (e) => {
                const action = e.target.closest('button').dataset.action;
                this.hideComment(commentId, action);
            });
        }
        
        // Save edit button
        const saveBtn = comment.querySelector('.save-edit');
        if (saveBtn) {
            saveBtn.addEventListener('click', () => this.saveEdit(commentId));
        }
        
        // Cancel edit button
        const cancelBtn = comment.querySelector('.cancel-edit');
        if (cancelBtn) {
            cancelBtn.addEventListener('click', () => this.cancelEdit(commentId));
        }
    }
    
    editComment(commentId) {
        const contentDiv = document.getElementById(`comment-content-${commentId}`);
        const editDiv = document.getElementById(`comment-edit-${commentId}`);
        
        contentDiv.classList.add('d-none');
        editDiv.classList.remove('d-none');
        
        const textarea = editDiv.querySelector('textarea');
        textarea.focus();
    }
    
    cancelEdit(commentId) {
        const contentDiv = document.getElementById(`comment-content-${commentId}`);
        const editDiv = document.getElementById(`comment-edit-${commentId}`);
        
        contentDiv.classList.remove('d-none');
        editDiv.classList.add('d-none');
    }
    
    async saveEdit(commentId) {
        const editDiv = document.getElementById(`comment-edit-${commentId}`);
        const textarea = editDiv.querySelector('textarea');
        const content = textarea.value.trim();
        
        if (!content) {
            this.showToast('Comment cannot be empty', 'warning');
            return;
        }
        
        const saveBtn = editDiv.querySelector('.save-edit');
        saveBtn.disabled = true;
        saveBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>Saving...';
        
        try {
            const response = await fetch(`/api/comment/edit/${commentId}`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': this.csrf_token
                },
                body: JSON.stringify({ content })
            });
            
            const data = await response.json();
            
            if (data.success) {
                // Update content
                const contentDiv = document.getElementById(`comment-content-${commentId}`);
                contentDiv.querySelector('p').textContent = content;
                
                // Cancel edit mode
                this.cancelEdit(commentId);
                
                // Show success
                this.showToast('Comment updated successfully!', 'success');
                
                // Update comment in DOM
                const commentEl = document.getElementById(`comment-${commentId}`);
                const usernameEl = commentEl.querySelector('h6');
                if (!usernameEl.querySelector('small')) {
                    usernameEl.innerHTML += '<small class="text-muted ms-2">(edited)</small>';
                }
            } else {
                this.showToast(data.message || 'Error updating comment', 'danger');
            }
        } catch (error) {
            console.error('Error updating comment:', error);
            this.showToast('Network error. Please try again.', 'danger');
        } finally {
            saveBtn.disabled = false;
            saveBtn.innerHTML = '<i class="fas fa-check me-1"></i>Save';
        }
    }
    
    async deleteComment(commentId) {
        if (!confirm('Are you sure you want to delete this comment?')) {
            return;
        }
        
        try {
            const response = await fetch(`/api/comment/delete/${commentId}`, {
                method: 'DELETE',
                headers: {
                    'X-CSRFToken': this.csrf_token
                }
            });
            
            const data = await response.json();
            
            if (data.success) {
                // Remove comment from DOM with animation
                const commentEl = document.getElementById(`comment-${commentId}`);
                commentEl.style.opacity = '0';
                commentEl.style.transition = 'opacity 0.3s';
                
                setTimeout(() => {
                    commentEl.remove();
                    
                    // Update comment count
                    this.updateCommentCount(data.comment_count);
                    
                    // Check if no comments left
                    const commentsList = document.getElementById('commentsList');
                    if (commentsList.children.length === 0) {
                        commentsList.innerHTML = `
                            <div class="text-center text-muted py-5">
                                <i class="fas fa-comments fa-3x mb-3 opacity-50"></i>
                                <p>No comments yet. Be the first to comment!</p>
                            </div>
                        `;
                    }
                }, 300);
                
                this.showToast('Comment deleted successfully', 'success');
            } else {
                this.showToast(data.message || 'Error deleting comment', 'danger');
            }
        } catch (error) {
            console.error('Error deleting comment:', error);
            this.showToast('Network error. Please try again.', 'danger');
        }
    }
    
    async flagComment(commentId, action) {
        let reason = null;
        
        if (action === 'flag') {
            reason = prompt('Reason for flagging this comment:', 'Inappropriate content');
            if (!reason) return;
        }
        
        try {
            const response = await fetch(`/api/comment/flag/${commentId}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': this.csrf_token
                },
                body: JSON.stringify({ action, reason })
            });
            
            const data = await response.json();
            
            if (data.success) {
                // Reload comment
                const commentEl = document.getElementById(`comment-${commentId}`);
                const parent = commentEl.parentElement;
                commentEl.remove();
                
                this.addCommentToDOM(data.comment, false);
                
                this.showToast(data.message, 'success');
            } else {
                this.showToast(data.message || 'Error flagging comment', 'danger');
            }
        } catch (error) {
            console.error('Error flagging comment:', error);
            this.showToast('Network error. Please try again.', 'danger');
        }
    }
    
    async hideComment(commentId, action) {
        try {
            const response = await fetch(`/api/comment/flag/${commentId}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': this.csrf_token
                },
                body: JSON.stringify({ action })
            });
            
            const data = await response.json();
            
            if (data.success) {
                const commentEl = document.getElementById(`comment-${commentId}`);
                if (action === 'hide') {
                    commentEl.classList.add('comment-hidden');
                } else {
                    commentEl.classList.remove('comment-hidden');
                }
                
                this.showToast(data.message, 'success');
            }
        } catch (error) {
            console.error('Error hiding comment:', error);
            this.showToast('Network error. Please try again.', 'danger');
        }
    }
    
    updateCharCount(textarea) {
        const counter = document.getElementById('charCounter');
        if (!counter) return;
        
        const current = textarea.value.length;
        const max = 1000;
        counter.textContent = `${current}/${max}`;
        
        if (current > max) {
            counter.classList.add('text-danger');
        } else {
            counter.classList.remove('text-danger');
        }
    }
    
    updateCommentCount(count) {
        const counters = document.querySelectorAll('.comment-count');
        counters.forEach(counter => {
            counter.textContent = count;
        });
    }
    
    addLoadMoreButton(nextPage) {
        const commentsList = document.getElementById('commentsList');
        const existing = document.getElementById('loadMoreBtn');
        if (existing) existing.remove();
        
        const btn = document.createElement('div');
        btn.id = 'loadMoreBtn';
        btn.className = 'text-center mt-4';
        btn.innerHTML = `
            <button class="btn btn-outline-primary" onclick="commentSystem.loadComments(${nextPage})">
                <i class="fas fa-chevron-down me-2"></i>Load More Comments
            </button>
        `;
        commentsList.appendChild(btn);
    }
    
    showToast(message, type = 'info') {
        // Create toast container if it doesn't exist
        let container = document.getElementById('toastContainer');
        if (!container) {
            container = document.createElement('div');
            container.id = 'toastContainer';
            container.className = 'toast-container position-fixed bottom-0 end-0 p-3';
            container.style.zIndex = '9999';
            document.body.appendChild(container);
        }
        
        const toastId = 'toast-' + Date.now();
        const toast = document.createElement('div');
        toast.id = toastId;
        toast.className = `toast align-items-center text-white bg-${type} border-0`;
        toast.setAttribute('role', 'alert');
        toast.innerHTML = `
            <div class="d-flex">
                <div class="toast-body">${message}</div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
            </div>
        `;
        
        container.appendChild(toast);
        
        const bsToast = new bootstrap.Toast(toast, { delay: 3000 });
        bsToast.show();
        
        toast.addEventListener('hidden.bs.toast', () => {
            toast.remove();
        });
    }
    
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

// Initialize when page loads
let commentSystem;
document.addEventListener('DOMContentLoaded', function() {
    const postId = document.body.dataset.postId;
    if (postId) {
        commentSystem = new CommentSystem(parseInt(postId));
    }
});
