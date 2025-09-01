// Main JavaScript for Quizera

// Initialize app when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
});

function initializeApp() {
    // Auto-hide flash messages after 5 seconds
    setTimeout(() => {
        const flashMessages = document.querySelectorAll('.flash-message');
        flashMessages.forEach(message => {
            message.style.transition = 'opacity 0.5s ease-out';
            message.style.opacity = '0';
            setTimeout(() => {
                message.remove();
            }, 500);
        });
    }, 5000);

    // Add loading states to forms
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', function() {
            const submitBtn = form.querySelector('button[type="submit"]');
            if (submitBtn) {
                submitBtn.disabled = true;
                const originalText = submitBtn.textContent;
                submitBtn.innerHTML = '<span class="loading"></span> ' + originalText;
                
                // Re-enable after 5 seconds as fallback
                setTimeout(() => {
                    submitBtn.disabled = false;
                    submitBtn.textContent = originalText;
                }, 5000);
            }
        });
    });

    // Add smooth scrolling to all anchor links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });

    // Add hover effects to cards
    const cards = document.querySelectorAll('.bg-white');
    cards.forEach(card => {
        card.addEventListener('mouseenter', function() {
            this.classList.add('card-hover');
        });
        card.addEventListener('mouseleave', function() {
            this.classList.remove('card-hover');
        });
    });
}

// Form validation utilities
function validateEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
}

function validatePassword(password) {
    return password.length >= 6;
}

function validateUsername(username) {
    return username.length >= 3 && /^[a-zA-Z0-9_]+$/.test(username);
}

// Show notification
function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `fixed top-4 right-4 p-4 rounded-lg shadow-lg z-50 ${
        type === 'success' ? 'bg-green-500' : 
        type === 'error' ? 'bg-red-500' : 
        type === 'warning' ? 'bg-yellow-500' : 
        'bg-blue-500'
    } text-white`;
    notification.textContent = message;
    
    document.body.appendChild(notification);
    
    // Animate in
    setTimeout(() => {
        notification.style.opacity = '1';
        notification.style.transform = 'translateX(0)';
    }, 100);
    
    // Remove after 5 seconds
    setTimeout(() => {
        notification.style.opacity = '0';
        notification.style.transform = 'translateX(100%)';
        setTimeout(() => {
            document.body.removeChild(notification);
        }, 300);
    }, 5000);
}

// Handle quiz interactions
function startQuiz(quizId) {
    if (confirm('Are you ready to start this quiz?')) {
        // Redirect to quiz page (to be implemented)
        window.location.href = `/quiz/${quizId}/start`;
    }
}

function editSubject(subjectId) {
    // Redirect to edit subject page (to be implemented)
    window.location.href = `/subject/${subjectId}/edit`;
}

function deleteSubject(subjectId, subjectName) {
    if (confirm(`Are you sure you want to delete the subject "${subjectName}"? This action cannot be undone.`)) {
        // Send delete request (to be implemented)
        fetch(`/subject/${subjectId}/delete`, {
            method: 'DELETE',
            headers: {
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            }
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                showNotification('Subject deleted successfully', 'success');
                // Reload the page to update the UI
                setTimeout(() => {
                    window.location.reload();
                }, 1000);
            } else {
                showNotification('Error deleting subject', 'error');
            }
        })
        .catch(error => {
            console.error('Error:', error);
            showNotification('Error deleting subject', 'error');
        });
    }
}

function editQuiz(quizId) {
    // Redirect to edit quiz page (to be implemented)
    window.location.href = `/quiz/${quizId}/edit`;
}

function deleteQuiz(quizId, quizTitle) {
    if (confirm(`Are you sure you want to delete the quiz "${quizTitle}"? This action cannot be undone.`)) {
        // Send delete request (to be implemented)
        fetch(`/quiz/${quizId}/delete`, {
            method: 'DELETE',
            headers: {
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            }
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                showNotification('Quiz deleted successfully', 'success');
                setTimeout(() => {
                    window.location.reload();
                }, 1000);
            } else {
                showNotification('Error deleting quiz', 'error');
            }
        })
        .catch(error => {
            console.error('Error:', error);
            showNotification('Error deleting quiz', 'error');
        });
    }
}

// Dashboard utilities
function refreshDashboard() {
    window.location.reload();
}

// Theme toggle (for future dark mode implementation)
function toggleTheme() {
    document.body.classList.toggle('dark-theme');
    localStorage.setItem('theme', document.body.classList.contains('dark-theme') ? 'dark' : 'light');
}

// Load saved theme
function loadTheme() {
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme === 'dark') {
        document.body.classList.add('dark-theme');
    }
}

// Initialize theme on load
document.addEventListener('DOMContentLoaded', loadTheme);

// Handle responsive navigation
function toggleMobileNav() {
    const nav = document.getElementById('mobile-nav');
    if (nav) {
        nav.classList.toggle('hidden');
    }
}

// Auto-save form data (for longer forms)
function autoSaveForm(formId) {
    const form = document.getElementById(formId);
    if (!form) return;
    
    const inputs = form.querySelectorAll('input, textarea, select');
    inputs.forEach(input => {
        input.addEventListener('input', () => {
            localStorage.setItem(`${formId}_${input.name}`, input.value);
        });
        
        // Load saved value
        const savedValue = localStorage.getItem(`${formId}_${input.name}`);
        if (savedValue && input.value === '') {
            input.value = savedValue;
        }
    });
    
    // Clear saved data on form submission
    form.addEventListener('submit', () => {
        inputs.forEach(input => {
            localStorage.removeItem(`${formId}_${input.name}`);
        });
    });
}

// Print functionality
function printPage() {
    window.print();
}

// Export data functionality (placeholder)
function exportData(format) {
    showNotification(`Exporting data in ${format} format...`, 'info');
    // Implementation would depend on backend API
}

// Search functionality
function searchContent(query) {
    const elements = document.querySelectorAll('[data-searchable]');
    elements.forEach(element => {
        const text = element.textContent.toLowerCase();
        if (text.includes(query.toLowerCase())) {
            element.style.display = 'block';
            element.classList.add('highlight-search');
        } else {
            element.style.display = 'none';
            element.classList.remove('highlight-search');
        }
    });
}

// Initialize search if search input exists
document.addEventListener('DOMContentLoaded', () => {
    const searchInput = document.getElementById('search');
    if (searchInput) {
        searchInput.addEventListener('input', (e) => {
            searchContent(e.target.value);
        });
    }
});

// Utility functions for future features
const Utils = {
    formatDate: (dateString) => {
        const date = new Date(dateString);
        return date.toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric'
        });
    },
    
    formatTime: (seconds) => {
        const minutes = Math.floor(seconds / 60);
        const remainingSeconds = seconds % 60;
        return `${minutes}:${remainingSeconds.toString().padStart(2, '0')}`;
    },
    
    debounce: (func, wait) => {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    },
    
    throttle: (func, limit) => {
        let inThrottle;
        return function() {
            const args = arguments;
            const context = this;
            if (!inThrottle) {
                func.apply(context, args);
                inThrottle = true;
                setTimeout(() => inThrottle = false, limit);
            }
        };
    }
};

// Make utilities globally available
window.QuizeraUtils = Utils;

// Enhanced main.js with edit/delete functionality

document.addEventListener('DOMContentLoaded', function() {
    // Flash message auto-hide
    const flashMessages = document.querySelectorAll('.flash-message');
    flashMessages.forEach(message => {
        setTimeout(() => {
            message.style.opacity = '0';
            setTimeout(() => {
                message.remove();
            }, 300);
        }, 5000);
    });

    // Subject Edit Buttons
    const subjectEditButtons = document.querySelectorAll('.subject-edit-btn');
    subjectEditButtons.forEach(button => {
        button.addEventListener('click', function() {
            const subjectId = this.getAttribute('data-subject-id');
            const subjectName = this.getAttribute('data-subject-name');
            const subjectDescription = this.getAttribute('data-subject-description');
            
            showEditSubjectModal(subjectId, subjectName, subjectDescription);
        });
    });

    // Subject Delete Buttons
    const subjectDeleteButtons = document.querySelectorAll('.subject-delete-btn');
    subjectDeleteButtons.forEach(button => {
        button.addEventListener('click', function() {
            const subjectId = this.getAttribute('data-subject-id');
            const subjectName = this.getAttribute('data-subject-name');
            
            if (confirm(`Are you sure you want to delete "${subjectName}"? This action cannot be undone.`)) {
                deleteSubject(subjectId);
            }
        });
    });

    // Quiz Edit Buttons
    const quizEditButtons = document.querySelectorAll('.quiz-edit-btn');
    quizEditButtons.forEach(button => {
        button.addEventListener('click', function() {
            const quizId = this.getAttribute('data-quiz-id');
            window.location.href = `/quiz/${quizId}/edit`;
        });
    });

    // Quiz Delete Buttons
    const quizDeleteButtons = document.querySelectorAll('.quiz-delete-btn');
    quizDeleteButtons.forEach(button => {
        button.addEventListener('click', function() {
            const quizId = this.getAttribute('data-quiz-id');
            const quizTitle = this.getAttribute('data-quiz-title');
            
            if (confirm(`Are you sure you want to delete "${quizTitle}"? This will also delete all questions. This action cannot be undone.`)) {
                deleteQuiz(quizId);
            }
        });
    });

    // Quiz Preview Buttons
    const quizPreviewButtons = document.querySelectorAll('.quiz-preview-btn');
    quizPreviewButtons.forEach(button => {
        button.addEventListener('click', function() {
            const quizId = this.getAttribute('data-quiz-id');
            window.location.href = `/quiz/${quizId}/preview`;
        });
    });
});

// Show Edit Subject Modal
function showEditSubjectModal(subjectId, name, description) {
    // Create modal HTML
    const modalHTML = `
        <div id="editSubjectModal" class="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
            <div class="relative top-20 mx-auto p-5 border w-96 shadow-lg rounded-md bg-white">
                <div class="mt-3">
                    <h3 class="text-lg font-medium text-gray-900 mb-4">Edit Subject</h3>
                    <form id="editSubjectForm">
                        <input type="hidden" id="editSubjectId" value="${subjectId}">
                        <div class="mb-4">
                            <label for="editSubjectName" class="block text-sm font-medium text-gray-700 mb-2">Subject Name</label>
                            <input type="text" id="editSubjectName" value="${name}" class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500" required>
                        </div>
                        <div class="mb-4">
                            <label for="editSubjectDescription" class="block text-sm font-medium text-gray-700 mb-2">Description</label>
                            <textarea id="editSubjectDescription" rows="3" class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500">${description}</textarea>
                        </div>
                        <div class="flex justify-end space-x-2">
                            <button type="button" onclick="closeEditSubjectModal()" class="px-4 py-2 bg-gray-300 text-gray-700 rounded-md hover:bg-gray-400 transition-colors">
                                Cancel
                            </button>
                            <button type="submit" class="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors">
                                Update Subject
                            </button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    `;
    
    // Add modal to page
    document.body.insertAdjacentHTML('beforeend', modalHTML);
    
    // Handle form submission
    document.getElementById('editSubjectForm').addEventListener('submit', function(e) {
        e.preventDefault();
        updateSubject();
    });
}

// Close Edit Subject Modal
function closeEditSubjectModal() {
    const modal = document.getElementById('editSubjectModal');
    if (modal) {
        modal.remove();
    }
}

// Update Subject
function updateSubject() {
    const subjectId = document.getElementById('editSubjectId').value;
    const name = document.getElementById('editSubjectName').value;
    const description = document.getElementById('editSubjectDescription').value;
    
    const formData = new FormData();
    formData.append('name', name);
    formData.append('description', description);
    
    fetch(`/subject/${subjectId}/edit`, {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            closeEditSubjectModal();
            location.reload(); // Refresh page to show changes
        } else {
            alert('Error updating subject: ' + data.message);
        }
    })
    .catch(error => {
        console.error('Error:', error);
        alert('Error updating subject. Please try again.');
    });
}

// Delete Subject
function deleteSubject(subjectId) {
    fetch(`/subject/${subjectId}/delete`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            location.reload(); // Refresh page to show changes
        } else {
            alert('Error deleting subject: ' + data.message);
        }
    })
    .catch(error => {
        console.error('Error:', error);
        alert('Error deleting subject. Please try again.');
    });
}

// Delete Quiz
function deleteQuiz(quizId) {
    fetch(`/quiz/${quizId}/delete`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            location.reload(); // Refresh page to show changes
        } else {
            alert('Error deleting quiz: ' + data.message);
        }
    })
    .catch(error => {
        console.error('Error:', error);
        alert('Error deleting quiz. Please try again.');
    });
}

// Add these functions to your existing main.js file

// Topic Edit and Delete Functionality
document.addEventListener('DOMContentLoaded', function() {
    // Topic Edit Buttons
    const topicEditButtons = document.querySelectorAll('.topic-edit-btn');
    topicEditButtons.forEach(button => {
        button.addEventListener('click', function() {
            const topicId = this.getAttribute('data-topic-id');
            const topicTitle = this.getAttribute('data-topic-title');
            const topicContent = this.getAttribute('data-topic-content') || '';
            const topicVideo = this.getAttribute('data-topic-video') || '';
            
            showEditTopicModal(topicId, topicTitle, topicContent, topicVideo);
        });
    });

    // Topic Delete Buttons
    const topicDeleteButtons = document.querySelectorAll('.topic-delete-btn');
    topicDeleteButtons.forEach(button => {
        button.addEventListener('click', function() {
            const topicId = this.getAttribute('data-topic-id');
            const topicTitle = this.getAttribute('data-topic-title');
            
            if (confirm(`Are you sure you want to delete "${topicTitle}"? This action cannot be undone.`)) {
                deleteTopic(topicId);
            }
        });
    });
});

// Show Edit Topic Modal
function showEditTopicModal(topicId, title, content, videoLink) {
    const modalHTML = `
        <div id="editTopicModal" class="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
            <div class="relative top-10 mx-auto p-5 border max-w-2xl shadow-lg rounded-md bg-white">
                <div class="mt-3">
                    <h3 class="text-lg font-medium text-gray-900 mb-4">Edit Topic</h3>
                    <form id="editTopicForm">
                        <input type="hidden" id="editTopicId" value="${topicId}">
                        <div class="mb-4">
                            <label for="editTopicTitle" class="block text-sm font-medium text-gray-700 mb-2">Topic Title</label>
                            <input type="text" id="editTopicTitle" value="${title}" class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500" required>
                        </div>
                        <div class="mb-4">
                            <label for="editTopicContent" class="block text-sm font-medium text-gray-700 mb-2">Content</label>
                            <textarea id="editTopicContent" rows="8" class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500">${content}</textarea>
                        </div>
                        <div class="mb-4">
                            <label for="editTopicVideo" class="block text-sm font-medium text-gray-700 mb-2">Video Link (Optional)</label>
                            <input type="url" id="editTopicVideo" value="${videoLink}" class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500" placeholder="https://youtube.com/watch?v=...">
                        </div>
                        <div class="flex justify-end space-x-2">
                            <button type="button" onclick="closeEditTopicModal()" class="px-4 py-2 bg-gray-300 text-gray-700 rounded-md hover:bg-gray-400 transition-colors">
                                Cancel
                            </button>
                            <button type="submit" class="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors">
                                Update Topic
                            </button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    `;
    
    document.body.insertAdjacentHTML('beforeend', modalHTML);
    
    // Handle form submission
    document.getElementById('editTopicForm').addEventListener('submit', function(e) {
        e.preventDefault();
        updateTopic();
    });
    
    // Close modal when clicking outside
    document.getElementById('editTopicModal').addEventListener('click', function(e) {
        if (e.target === this) {
            closeEditTopicModal();
        }
    });
}

// Close Edit Topic Modal
function closeEditTopicModal() {
    const modal = document.getElementById('editTopicModal');
    if (modal) {
        modal.remove();
    }
}

// Update Topic
function updateTopic() {
    const topicId = document.getElementById('editTopicId').value;
    const title = document.getElementById('editTopicTitle').value;
    const content = document.getElementById('editTopicContent').value;
    const videoLink = document.getElementById('editTopicVideo').value;
    
    const formData = new FormData();
    formData.append('title', title);
    formData.append('content_text', content);
    formData.append('video_link', videoLink);
    
    // Show loading state
    const submitBtn = document.querySelector('#editTopicForm button[type="submit"]');
    const originalText = submitBtn.textContent;
    submitBtn.disabled = true;
    submitBtn.textContent = 'Updating...';
    
    fetch(`/topic/${topicId}/edit`, {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            closeEditTopicModal();
            showNotification('Topic updated successfully!', 'success');
            setTimeout(() => {
                location.reload();
            }, 1000);
        } else {
            showNotification('Error updating topic: ' + (data.message || 'Unknown error'), 'error');
            submitBtn.disabled = false;
            submitBtn.textContent = originalText;
        }
    })
    .catch(error => {
        console.error('Error:', error);
        showNotification('Error updating topic. Please try again.', 'error');
        submitBtn.disabled = false;
        submitBtn.textContent = originalText;
    });
}

// Delete Topic
function deleteTopic(topicId) {
    fetch(`/topic/${topicId}/delete`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showNotification('Topic deleted successfully!', 'success');
            setTimeout(() => {
                // If we're on the topic detail page, go back to subject
                if (window.location.pathname.includes('/topic/')) {
                    window.history.back();
                } else {
                    location.reload();
                }
            }, 1000);
        } else {
            showNotification('Error deleting topic: ' + (data.message || 'Unknown error'), 'error');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        showNotification('Error deleting topic. Please try again.', 'error');
    });
}

// Enhanced notification function (if not already in your main.js)
function showNotification(message, type = 'info') {
    // Remove any existing notifications
    const existingNotifications = document.querySelectorAll('.notification');
    existingNotifications.forEach(notification => notification.remove());
    
    const notification = document.createElement('div');
    notification.className = `notification fixed top-4 right-4 p-4 rounded-lg shadow-lg z-50 transform translate-x-full transition-transform duration-300 ${
        type === 'success' ? 'bg-green-500' : 
        type === 'error' ? 'bg-red-500' : 
        type === 'warning' ? 'bg-yellow-500' : 
        'bg-blue-500'
    } text-white`;
    
    notification.innerHTML = `
        <div class="flex items-center">
            <i class="fas ${
                type === 'success' ? 'fa-check-circle' : 
                type === 'error' ? 'fa-exclamation-circle' : 
                type === 'warning' ? 'fa-exclamation-triangle' : 
                'fa-info-circle'
            } mr-2"></i>
            <span>${message}</span>
            <button onclick="this.parentElement.parentElement.remove()" class="ml-4 text-white hover:text-gray-200">
                <i class="fas fa-times"></i>
            </button>
        </div>
    `;
    
    document.body.appendChild(notification);
    
    // Animate in
    setTimeout(() => {
        notification.classList.remove('translate-x-full');
    }, 100);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        if (notification.parentElement) {
            notification.classList.add('translate-x-full');
            setTimeout(() => {
                if (notification.parentElement) {
                    notification.remove();
                }
            }, 300);
        }
    }, 5000);
}

// Escape key to close modals
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
        closeEditSubjectModal();
        closeEditTopicModal();
    }
});

// Prevent form submission on Enter key in modal inputs (except textarea)
document.addEventListener('keydown', function(e) {
    if (e.key === 'Enter' && e.target.tagName === 'INPUT' && e.target.closest('.modal')) {
        e.preventDefault();
    }
});

// Auto-resize textareas
function autoResizeTextarea(textarea) {
    textarea.style.height = 'auto';
    textarea.style.height = textarea.scrollHeight + 'px';
}

// Initialize auto-resize for textareas in modals
document.addEventListener('input', function(e) {
    if (e.target.tagName === 'TEXTAREA') {
        autoResizeTextarea(e.target);
    }
});

// Video link validation helper
function validateVideoLink(url) {
    if (!url) return true; // Empty is allowed
    
    const videoPatterns = [
        /^https:\/\/(?:www\.)?youtube\.com\/watch\?v=[\w-]+/,
        /^https:\/\/youtu\.be\/[\w-]+/,
        /^https:\/\/(?:www\.)?vimeo\.com\/\d+/,
        /^https:\/\/.*\.(mp4|avi|mov|wmv|flv|webm)$/i
    ];
    
    return videoPatterns.some(pattern => pattern.test(url));
}

// Add video link validation to the edit topic form
document.addEventListener('input', function(e) {
    if (e.target.id === 'editTopicVideo') {
        const url = e.target.value;
        const isValid = validateVideoLink(url);
        
        if (url && !isValid) {
            e.target.setCustomValidity('Please enter a valid video URL (YouTube, Vimeo, or direct video file)');
        } else {
            e.target.setCustomValidity('');
        }
    }
});

// Smooth scrolling for anchor links
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            target.scrollIntoView({
                behavior: 'smooth'
            });
        }
    });
});

// Real-time search functionality for courses/subjects
document.addEventListener('DOMContentLoaded', function() {
    const searchInput = document.getElementById('searchInput');
    const subjectsContainer = document.querySelector('.subjects-grid');
    
    if (searchInput && subjectsContainer) {
        let searchTimeout;
        
        searchInput.addEventListener('input', function() {
            clearTimeout(searchTimeout);
            const searchTerm = this.value.toLowerCase().trim();
            
            // Debounce search to avoid too many API calls
            searchTimeout = setTimeout(() => {
                filterSubjects(searchTerm);
            }, 300);
        });
        
        function filterSubjects(searchTerm) {
            const subjectCards = subjectsContainer.querySelectorAll('.subject-card');
            
            subjectCards.forEach(card => {
                const title = card.querySelector('.subject-title').textContent.toLowerCase();
                const description = card.querySelector('.subject-description').textContent.toLowerCase();
                const teacher = card.querySelector('.subject-teacher').textContent.toLowerCase();
                
                const matches = title.includes(searchTerm) || 
                               description.includes(searchTerm) || 
                               teacher.includes(searchTerm);
                
                if (matches || searchTerm === '') {
                    card.style.display = 'block';
                    card.classList.remove('hidden');
                } else {
                    card.style.display = 'none';
                    card.classList.add('hidden');
                }
            });
            
            // Show "no results" message if needed
            const visibleCards = subjectsContainer.querySelectorAll('.subject-card:not(.hidden)');
            const noResultsMsg = document.getElementById('noResultsMessage');
            
            if (visibleCards.length === 0 && searchTerm !== '') {
                if (!noResultsMsg) {
                    const message = document.createElement('div');
                    message.id = 'noResultsMessage';
                    message.className = 'text-center py-8';
                    message.innerHTML = `
                        <div class="text-gray-500">
                            <svg class="w-16 h-16 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path>
                            </svg>
                            <h3 class="text-lg font-medium mb-2">No subjects found</h3>
                            <p>Try adjusting your search terms</p>
                        </div>
                    `;
                    subjectsContainer.appendChild(message);
                }
            } else if (noResultsMsg) {
                noResultsMsg.remove();
            }
        }
    }
});

// Dashboard functionality for edit/delete actions
function editSubject(subjectId, currentName, currentDescription) {
    const name = prompt('Enter subject name:', currentName);
    if (name === null) return; // User cancelled
    
    const description = prompt('Enter subject description:', currentDescription);
    if (description === null) return; // User cancelled
    
    // Create form data
    const formData = new FormData();
    formData.append('name', name);
    formData.append('description', description);
    
    fetch(`/subject/${subjectId}/edit`, {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            location.reload(); // Reload to show changes
        } else {
            alert('Error: ' + data.message);
        }
    })
    .catch(error => {
        console.error('Error:', error);
        alert('An error occurred while updating the subject.');
    });
}

function deleteSubject(subjectId, subjectName) {
    if (confirm(`Are you sure you want to delete "${subjectName}"? This action cannot be undone and will also delete all associated topics and quizzes.`)) {
        fetch(`/subject/${subjectId}/delete`, {
            method: 'POST'
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                location.reload(); // Reload to show changes
            } else {
                alert('Error: ' + data.message);
            }
        })
        .catch(error => {
            console.error('Error:', error);
            alert('An error occurred while deleting the subject.');
        });
    }
}

function deleteQuiz(quizId, quizTitle) {
    if (confirm(`Are you sure you want to delete "${quizTitle}"? This action cannot be undone and will also delete all associated questions.`)) {
        fetch(`/quiz/${quizId}/delete`, {
            method: 'POST'
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                location.reload(); // Reload to show changes
            } else {
                alert('Error: ' + data.message);
            }
        })
        .catch(error => {
            console.error('Error:', error);
            alert('An error occurred while deleting the quiz.');
        });
    }
}

// Profile image upload preview
function previewProfileImage(input) {
    if (input.files && input.files[0]) {
        const reader = new FileReader();
        reader.onload = function(e) {
            const preview = document.getElementById('profileImagePreview');
            if (preview) {
                preview.src = e.target.result;
            }
        };
        reader.readAsDataURL(input.files[0]);
    }
}

// Form validation
function validateForm(formId) {
    const form = document.getElementById(formId);
    const requiredFields = form.querySelectorAll('input[required], textarea[required], select[required]');
    let isValid = true;
    
    requiredFields.forEach(field => {
        if (!field.value.trim()) {
            field.classList.add('border-red-500');
            isValid = false;
        } else {
            field.classList.remove('border-red-500');
        }
    });
    
    return isValid;
}

// Mobile menu toggle (if you add mobile navigation later)
function toggleMobileMenu() {
    const mobileMenu = document.getElementById('mobileMenu');
    if (mobileMenu) {
        mobileMenu.classList.toggle('hidden');
    }
}

// main.js - Dashboard JavaScript Functions
console.log('main.js loaded!');

document.addEventListener('DOMContentLoaded', function() {
    console.log('DOM Content Loaded in main.js!');
    
    // Quiz Take Button Handler - with debugging
    const takeBtns = document.querySelectorAll('.quiz-take-btn');
    console.log('Found quiz-take-btn elements:', takeBtns.length);
    
    takeBtns.forEach((button, index) => {
        console.log(`Setting up take button ${index}:`, button);
        button.addEventListener('click', function(e) {
            console.log('Quiz take button clicked!');
            const quizId = this.getAttribute('data-quiz-id');
            console.log('Quiz ID:', quizId);
            
            if (quizId) {
                const url = `/quiz/${quizId}/take`;
                console.log('Navigating to:', url);
                window.location.href = url;
            } else {
                console.error('No quiz ID found!');
            }
        });
    });

    // Quiz Results Button Handler - with debugging
    const resultsBtns = document.querySelectorAll('.quiz-results-btn');
    console.log('Found quiz-results-btn elements:', resultsBtns.length);
    
    resultsBtns.forEach((button, index) => {
        console.log(`Setting up results button ${index}:`, button);
        button.addEventListener('click', function(e) {
            console.log('Quiz results button clicked!');
            const quizId = this.getAttribute('data-quiz-id');
            console.log('Quiz ID:', quizId);
            
            if (quizId) {
                const url = `/quiz/${quizId}/results`;
                console.log('Navigating to:', url);
                window.location.href = url;
            } else {
                console.error('No quiz ID found!');
            }
        });
    });

    // Quiz Preview Button Handler
    const previewBtns = document.querySelectorAll('.quiz-preview-btn');
    console.log('Found quiz-preview-btn elements:', previewBtns.length);
    
    previewBtns.forEach(button => {
        button.addEventListener('click', function() {
            console.log('Quiz preview button clicked!');
            const quizId = this.getAttribute('data-quiz-id');
            console.log('Preview Quiz ID:', quizId);
            
            if (quizId) {
                const url = `/quiz/${quizId}/preview`;
                console.log('Navigating to preview:', url);
                window.location.href = url;
            }
        });
    });

    // Subject Edit Button Handler
    const subjectEditBtns = document.querySelectorAll('.subject-edit-btn');
    console.log('Found subject-edit-btn elements:', subjectEditBtns.length);
    
    subjectEditBtns.forEach(button => {
        button.addEventListener('click', function() {
            console.log('Subject edit button clicked!');
            const subjectId = this.getAttribute('data-subject-id');
            const subjectName = this.getAttribute('data-subject-name');
            const subjectDescription = this.getAttribute('data-subject-description');
            
            showEditSubjectModal(subjectId, subjectName, subjectDescription);
        });
    });

    // Subject Delete Button Handler
    const subjectDeleteBtns = document.querySelectorAll('.subject-delete-btn');
    console.log('Found subject-delete-btn elements:', subjectDeleteBtns.length);
    
    subjectDeleteBtns.forEach(button => {
        button.addEventListener('click', function() {
            console.log('Subject delete button clicked!');
            const subjectId = this.getAttribute('data-subject-id');
            const subjectName = this.getAttribute('data-subject-name');
            
            showDeleteSubjectModal(subjectId, subjectName);
        });
    });

    // Quiz Delete Button Handler
    const quizDeleteBtns = document.querySelectorAll('.quiz-delete-btn');
    console.log('Found quiz-delete-btn elements:', quizDeleteBtns.length);
    
    quizDeleteBtns.forEach(button => {
        button.addEventListener('click', function() {
            console.log('Quiz delete button clicked!');
            const quizId = this.getAttribute('data-quiz-id');
            const quizTitle = this.getAttribute('data-quiz-title');
            
            showDeleteQuizModal(quizId, quizTitle);
        });
    });

    // Topic Delete Button Handler
    const topicDeleteBtns = document.querySelectorAll('.topic-delete-btn');
    console.log('Found topic-delete-btn elements:', topicDeleteBtns.length);
    
    topicDeleteBtns.forEach(button => {
        button.addEventListener('click', function() {
            console.log('Topic delete button clicked!');
            const topicId = this.getAttribute('data-topic-id');
            const topicTitle = this.getAttribute('data-topic-title');
            
            showDeleteTopicModal(topicId, topicTitle);
        });
    });

    // Topic Edit Button Handler
    const topicEditBtns = document.querySelectorAll('.topic-edit-btn');
    console.log('Found topic-edit-btn elements:', topicEditBtns.length);
    
    topicEditBtns.forEach(button => {
        button.addEventListener('click', function() {
            console.log('Topic edit button clicked!');
            const topicId = this.getAttribute('data-topic-id');
            const url = `/topic/${topicId}/edit`;
            console.log('Navigating to edit topic:', url);
            window.location.href = url;
        });
    });
});

// Modal Functions
function showEditSubjectModal(subjectId, name, description) {
    console.log('Showing edit subject modal for:', subjectId, name);
    
    // Create modal HTML
    const modalHTML = `
        <div id="editSubjectModal" class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
            <div class="bg-white rounded-lg p-8 max-w-md w-full mx-4">
                <h3 class="text-xl font-semibold text-gray-800 mb-4">Edit Subject</h3>
                <form id="editSubjectForm">
                    <div class="mb-4">
                        <label for="subjectName" class="block text-sm font-medium text-gray-700 mb-2">Subject Name</label>
                        <input type="text" id="subjectName" name="name" value="${name}" 
                               class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500" required>
                    </div>
                    <div class="mb-6">
                        <label for="subjectDescription" class="block text-sm font-medium text-gray-700 mb-2">Description</label>
                        <textarea id="subjectDescription" name="description" rows="3" 
                                  class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500">${description || ''}</textarea>
                    </div>
                    <div class="flex justify-end space-x-3">
                        <button type="button" onclick="closeModal('editSubjectModal')" 
                                class="px-4 py-2 bg-gray-300 text-gray-700 rounded-md hover:bg-gray-400 transition-colors">
                            Cancel
                        </button>
                        <button type="submit" 
                                class="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors">
                            Update Subject
                        </button>
                    </div>
                </form>
            </div>
        </div>
    `;
    
    // Add modal to DOM
    document.body.insertAdjacentHTML('beforeend', modalHTML);
    
    // Handle form submission
    document.getElementById('editSubjectForm').addEventListener('submit', function(e) {
        e.preventDefault();
        console.log('Submitting subject edit form');
        
        const formData = new FormData(this);
        
        fetch(`/subject/${subjectId}/edit`, {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            console.log('Edit response:', data);
            if (data.success) {
                location.reload();
            } else {
                alert('Error: ' + data.message);
            }
        })
        .catch(error => {
            console.error('Error:', error);
            alert('An error occurred while updating the subject.');
        });
    });
}

function showDeleteSubjectModal(subjectId, name) {
    console.log('Showing delete subject modal for:', subjectId, name);
    
    const modalHTML = `
        <div id="deleteSubjectModal" class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
            <div class="bg-white rounded-lg p-8 max-w-md w-full mx-4">
                <h3 class="text-xl font-semibold text-gray-800 mb-4">Delete Subject</h3>
                <p class="text-gray-600 mb-6">Are you sure you want to delete "<strong>${name}</strong>"? This will also delete all associated topics and quizzes. This action cannot be undone.</p>
                <div class="flex justify-end space-x-3">
                    <button type="button" onclick="closeModal('deleteSubjectModal')" 
                            class="px-4 py-2 bg-gray-300 text-gray-700 rounded-md hover:bg-gray-400 transition-colors">
                        Cancel
                    </button>
                    <button type="button" onclick="deleteSubject('${subjectId}')" 
                            class="px-4 py-2 bg-red-600 text-white rounded-md hover:bg-red-700 transition-colors">
                        Delete Subject
                    </button>
                </div>
            </div>
        </div>
    `;
    
    document.body.insertAdjacentHTML('beforeend', modalHTML);
}

function showDeleteQuizModal(quizId, title) {
    console.log('Showing delete quiz modal for:', quizId, title);
    
    const modalHTML = `
        <div id="deleteQuizModal" class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
            <div class="bg-white rounded-lg p-8 max-w-md w-full mx-4">
                <h3 class="text-xl font-semibold text-gray-800 mb-4">Delete Quiz</h3>
                <p class="text-gray-600 mb-6">Are you sure you want to delete "<strong>${title}</strong>"? This will also delete all questions and student results. This action cannot be undone.</p>
                <div class="flex justify-end space-x-3">
                    <button type="button" onclick="closeModal('deleteQuizModal')" 
                            class="px-4 py-2 bg-gray-300 text-gray-700 rounded-md hover:bg-gray-400 transition-colors">
                        Cancel
                    </button>
                    <button type="button" onclick="deleteQuiz('${quizId}')" 
                            class="px-4 py-2 bg-red-600 text-white rounded-md hover:bg-red-700 transition-colors">
                        Delete Quiz
                    </button>
                </div>
            </div>
        </div>
    `;
    
    document.body.insertAdjacentHTML('beforeend', modalHTML);
}

function showDeleteTopicModal(topicId, title) {
    console.log('Showing delete topic modal for:', topicId, title);
    
    const modalHTML = `
        <div id="deleteTopicModal" class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
            <div class="bg-white rounded-lg p-8 max-w-md w-full mx-4">
                <h3 class="text-xl font-semibold text-gray-800 mb-4">Delete Topic</h3>
                <p class="text-gray-600 mb-6">Are you sure you want to delete "<strong>${title}</strong>"? This action cannot be undone.</p>
                <div class="flex justify-end space-x-3">
                    <button type="button" onclick="closeModal('deleteTopicModal')" 
                            class="px-4 py-2 bg-gray-300 text-gray-700 rounded-md hover:bg-gray-400 transition-colors">
                        Cancel
                    </button>
                    <button type="button" onclick="deleteTopic('${topicId}')" 
                            class="px-4 py-2 bg-red-600 text-white rounded-md hover:bg-red-700 transition-colors">
                        Delete Topic
                    </button>
                </div>
            </div>
        </div>
    `;
    
    document.body.insertAdjacentHTML('beforeend', modalHTML);
}

// Delete Functions
function deleteSubject(subjectId) {
    console.log('Deleting subject:', subjectId);
    
    fetch(`/subject/${subjectId}/delete`, {
        method: 'POST'
    })
    .then(response => response.json())
    .then(data => {
        console.log('Delete subject response:', data);
        if (data.success) {
            location.reload();
        } else {
            alert('Error: ' + data.message);
        }
    })
    .catch(error => {
        console.error('Error deleting subject:', error);
        alert('An error occurred while deleting the subject.');
    });
}

function deleteQuiz(quizId) {
    console.log('Deleting quiz:', quizId);
    
    fetch(`/quiz/${quizId}/delete`, {
        method: 'POST'
    })
    .then(response => response.json())
    .then(data => {
        console.log('Delete quiz response:', data);
        if (data.success) {
            location.reload();
        } else {
            alert('Error: ' + data.message);
        }
    })
    .catch(error => {
        console.error('Error deleting quiz:', error);
        alert('An error occurred while deleting the quiz.');
    });
}

function deleteTopic(topicId) {
    console.log('Deleting topic:', topicId);
    
    fetch(`/topic/${topicId}/delete`, {
        method: 'POST'
    })
    .then(response => response.json())
    .then(data => {
        console.log('Delete topic response:', data);
        if (data.success) {
            location.reload();
        } else {
            alert('Error: ' + data.message);
        }
    })
    .catch(error => {
        console.error('Error deleting topic:', error);
        alert('An error occurred while deleting the topic.');
    });
}

// Utility Functions
function closeModal(modalId) {
    console.log('Closing modal:', modalId);
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.remove();
    }
}

// Close modals when clicking outside
document.addEventListener('click', function(e) {
    if (e.target.classList.contains('fixed') && e.target.classList.contains('inset-0')) {
        console.log('Closing modal by clicking outside');
        e.target.remove();
    }
});

// FOR SEARCH_PROFILE.HTML, AND VIEW_PROFILE.HMTL

// Search functionality enhancements
document.addEventListener('DOMContentLoaded', function() {
    
    // Auto-complete search suggestions
    const searchInput = document.querySelector('input[name="q"]');
    if (searchInput) {
        let debounceTimer;
        
        searchInput.addEventListener('input', function() {
            clearTimeout(debounceTimer);
            const query = this.value.trim();
            
            // Debounce search suggestions
            debounceTimer = setTimeout(() => {
                if (query.length >= 2) {
                    showSearchSuggestions(query);
                } else {
                    hideSearchSuggestions();
                }
            }, 300);
        });
        
        // Hide suggestions when clicking outside
        document.addEventListener('click', function(e) {
            if (!searchInput.contains(e.target)) {
                hideSearchSuggestions();
            }
        });
        
        // Handle keyboard navigation in search
        searchInput.addEventListener('keydown', function(e) {
            const suggestions = document.querySelector('.search-suggestions');
            if (!suggestions) return;
            
            const items = suggestions.querySelectorAll('.suggestion-item');
            let currentIndex = Array.from(items).findIndex(item => 
                item.classList.contains('highlighted')
            );
            
            switch(e.key) {
                case 'ArrowDown':
                    e.preventDefault();
                    currentIndex = (currentIndex + 1) % items.length;
                    highlightSuggestion(items, currentIndex);
                    break;
                case 'ArrowUp':
                    e.preventDefault();
                    currentIndex = currentIndex <= 0 ? items.length - 1 : currentIndex - 1;
                    highlightSuggestion(items, currentIndex);
                    break;
                case 'Enter':
                    if (currentIndex >= 0 && items[currentIndex]) {
                        e.preventDefault();
                        items[currentIndex].click();
                    }
                    break;
                case 'Escape':
                    hideSearchSuggestions();
                    searchInput.blur();
                    break;
            }
        });
    }
    
    // Profile card animations
    const profileCards = document.querySelectorAll('.profile-card');
    profileCards.forEach(card => {
        card.addEventListener('mouseenter', function() {
            this.style.transform = 'translateY(-4px)';
        });
        
        card.addEventListener('mouseleave', function() {
            this.style.transform = 'translateY(0)';
        });
    });
    
    // Lazy loading for profile images
    const profileImages = document.querySelectorAll('img[data-src]');
    if (profileImages.length > 0) {
        const imageObserver = new IntersectionObserver((entries, observer) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    const img = entry.target;
                    img.src = img.dataset.src;
                    img.removeAttribute('data-src');
                    observer.unobserve(img);
                }
            });
        });
        
        profileImages.forEach(img => imageObserver.observe(img));
    }
    
    // Statistics counter animation
    const statNumbers = document.querySelectorAll('.stat-number');
    const statsObserver = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                animateCounter(entry.target);
                statsObserver.unobserve(entry.target);
            }
        });
    });
    
    statNumbers.forEach(stat => statsObserver.observe(stat));
    
    // Achievement badge hover effects
    const achievementBadges = document.querySelectorAll('.achievement-badge');
    achievementBadges.forEach(badge => {
        badge.addEventListener('mouseenter', function() {
            this.style.transform = 'scale(1.1) rotate(5deg)';
        });
        
        badge.addEventListener('mouseleave', function() {
            this.style.transform = 'scale(1) rotate(0deg)';
        });
    });
    
    // Filter buttons functionality
    const filterButtons = document.querySelectorAll('.filter-btn');
    filterButtons.forEach(btn => {
        btn.addEventListener('click', function() {
            // Remove active class from all buttons
            filterButtons.forEach(b => b.classList.remove('active'));
            // Add active class to clicked button
            this.classList.add('active');
            
            // Update URL with filter
            const role = this.dataset.role;
            const url = new URL(window.location);
            if (role) {
                url.searchParams.set('role', role);
            } else {
                url.searchParams.delete('role');
            }
            window.history.pushState({}, '', url);
            
            // You can add AJAX functionality here to filter without page reload
        });
    });
    
    // Recent activity timestamps
    updateRelativeTimestamps();
    setInterval(updateRelativeTimestamps, 60000); // Update every minute
    
    // Smooth scroll for anchor links
    const anchorLinks = document.querySelectorAll('a[href^="#"]');
    anchorLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });
});

// Search suggestions functionality
function showSearchSuggestions(query) {
    // This would typically make an AJAX call to get suggestions
    // For now, we'll create a placeholder
    const searchContainer = document.querySelector('.search-container') || 
                           document.querySelector('input[name="q"]').parentElement;
    
    // Remove existing suggestions
    hideSearchSuggestions();
    
    // Create suggestions container
    const suggestions = document.createElement('div');
    suggestions.className = 'search-suggestions absolute top-full left-0 right-0 bg-white border border-gray-200 rounded-lg shadow-lg z-50 mt-1';
    
    // Mock suggestions (replace with actual API call)
    const mockSuggestions = [
        { type: 'user', name: 'John Doe', role: 'teacher' },
        { type: 'user', name: 'Jane Smith', role: 'student' },
        { type: 'subject', name: 'Data Structures' }
    ].filter(item => 
        item.name.toLowerCase().includes(query.toLowerCase())
    );
    
    if (mockSuggestions.length > 0) {
        mockSuggestions.forEach(suggestion => {
            const item = document.createElement('div');
            item.className = 'suggestion-item px-4 py-2 hover:bg-gray-100 cursor-pointer border-b border-gray-100 last:border-b-0';
            item.innerHTML = `
                <div class="flex items-center space-x-2">
                    <div class="w-2 h-2 rounded-full ${suggestion.role === 'teacher' ? 'bg-blue-500' : 'bg-green-500'}"></div>
                    <span class="font-medium">${suggestion.name}</span>
                    <span class="text-xs text-gray-500">${suggestion.role || suggestion.type}</span>
                </div>
            `;
            
            item.addEventListener('click', () => {
                document.querySelector('input[name="q"]').value = suggestion.name;
                hideSearchSuggestions();
                // Trigger search
                document.querySelector('form').submit();
            });
            
            suggestions.appendChild(item);
        });
        
        searchContainer.appendChild(suggestions);
    }
}

function hideSearchSuggestions() {
    const suggestions = document.querySelector('.search-suggestions');
    if (suggestions) {
        suggestions.remove();
    }
}

function highlightSuggestion(items, index) {
    items.forEach(item => item.classList.remove('highlighted'));
    if (items[index]) {
        items[index].classList.add('highlighted');
        items[index].style.backgroundColor = '#EBF4FF';
    }
}

// Animate counter numbers
function animateCounter(element) {
    const target = parseInt(element.textContent) || 0;
    const increment = target / 20;
    let current = 0;
    
    const timer = setInterval(() => {
        current += increment;
        if (current >= target) {
            element.textContent = target;
            clearInterval(timer);
        } else {
            element.textContent = Math.floor(current);
        }
    }, 50);
}

// Update relative timestamps
function updateRelativeTimestamps() {
    const timestamps = document.querySelectorAll('[data-timestamp]');
    timestamps.forEach(element => {
        const timestamp = parseInt(element.dataset.timestamp);
        const now = Date.now();
        const diff = now - timestamp;
        
        const minutes = Math.floor(diff / 60000);
        const hours = Math.floor(diff / 3600000);
        const days = Math.floor(diff / 86400000);
        
        let relative;
        if (minutes < 1) {
            relative = 'Just now';
        } else if (minutes < 60) {
            relative = `${minutes}m ago`;
        } else if (hours < 24) {
            relative = `${hours}h ago`;
        } else if (days < 7) {
            relative = `${days}d ago`;
        } else {
            const date = new Date(timestamp);
            relative = date.toLocaleDateString();
        }
        
        element.textContent = relative;
    });
}

// Utility function for AJAX requests
function fetchJSON(url, options = {}) {
    return fetch(url, {
        headers: {
            'Content-Type': 'application/json',
            ...options.headers
        },
        ...options
    })
    .then(response => {
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return response.json();
    });
}

// Export functions for use in other scripts
window.SearchUtils = {
    showSearchSuggestions,
    hideSearchSuggestions,
    animateCounter,
    updateRelativeTimestamps,
    fetchJSON
};

// for flash messages

document.addEventListener('DOMContentLoaded', function() {
    // Auto-hide flash messages after 5 seconds
    const flashMessages = document.querySelectorAll('.flash-message');
    
    flashMessages.forEach(function(message, index) {
        // Stagger the appearance of multiple messages
        setTimeout(() => {
            message.style.animationDelay = (index * 100) + 'ms';
        }, 0);
        
        // Auto-hide after 5 seconds
        setTimeout(function() {
            hideFlashMessage(message);
        }, 5000 + (index * 100));
    });
    
    // Add click event to close buttons
    document.addEventListener('click', function(e) {
        if (e.target.classList.contains('close-btn')) {
            hideFlashMessage(e.target.closest('.flash-message'));
        }
    });
});

function hideFlashMessage(message) {
    message.classList.add('fade-out');
    setTimeout(function() {
        if (message.parentNode) {
            message.parentNode.removeChild(message);
        }
    }, 300);
}

// Function to add flash messages dynamically (for AJAX responses)
function showFlashMessage(message, category = 'info') {
    const container = document.querySelector('.flash-container') || createFlashContainer();
    
    const flashDiv = document.createElement('div');
    flashDiv.className = `flash-message ${category}`;
    flashDiv.innerHTML = `
        ${message}
        <button class="close-btn" type="button">&times;</button>
    `;
    
    container.appendChild(flashDiv);
    
    // Auto-hide after 5 seconds
    setTimeout(() => hideFlashMessage(flashDiv), 5000);
}

function createFlashContainer() {
    const container = document.createElement('div');
    container.className = 'flash-container';
    document.body.appendChild(container);
    return container;
}