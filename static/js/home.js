document.addEventListener('DOMContentLoaded', function() {
    const searchInput = document.getElementById('searchInput');
    const clearSearch = document.getElementById('clearSearch');
    const teacherFilter = document.getElementById('teacherFilter');
    const sortBy = document.getElementById('sortBy');
    const gridView = document.getElementById('gridView');
    const listView = document.getElementById('listView');
    const subjectsGrid = document.getElementById('subjectsGrid');
    const subjectsList = document.getElementById('subjectsList');
    const noResultsMessage = document.getElementById('noResultsMessage');
    const resultsCount = document.getElementById('resultsCount');
    const resetFilters = document.getElementById('resetFilters');
    
    // Quick enrollment elements (only for students)
    const quickEnrollModal = document.getElementById('quickEnrollModal');
    const quickEnrollText = document.getElementById('quickEnrollText');
    const confirmQuickEnroll = document.getElementById('confirmQuickEnroll');
    const cancelQuickEnroll = document.getElementById('cancelQuickEnroll');
    
    let currentView = 'grid';
    let allSubjects = [];
    let filteredSubjects = [];
    
    // Initialize
    if (subjectsGrid || subjectsList) {
        initializeSubjects();
        populateTeacherFilter();
    }
    
    function initializeSubjects() {
        // Get all subject cards from both grid and list views
        const gridCards = Array.from(subjectsGrid?.querySelectorAll('.subject-card') || []);
        const listCards = Array.from(subjectsList?.querySelectorAll('.subject-card-list') || []);
        
        allSubjects = gridCards.map((card, index) => {
            const listCard = listCards[index];
            return {
                gridElement: card,
                listElement: listCard,
                name: card.dataset.subjectName || '',
                description: card.dataset.subjectDescription || '',
                teacher: card.dataset.subjectTeacher || '',
                date: card.dataset.subjectDate || '',
                visible: true
            };
        });
        
        filteredSubjects = [...allSubjects];
    }
    
    function populateTeacherFilter() {
        if (!teacherFilter) return;
        
        const teachers = [...new Set(allSubjects.map(s => s.teacher).filter(Boolean))];
        teachers.sort();
        
        teachers.forEach(teacher => {
            const option = document.createElement('option');
            option.value = teacher;
            option.textContent = teacher.charAt(0).toUpperCase() + teacher.slice(1);
            teacherFilter.appendChild(option);
        });
    }
    
    function filterAndSortSubjects() {
        const searchTerm = searchInput?.value.toLowerCase() || '';
        const selectedTeacher = teacherFilter?.value || '';
        const sortOption = sortBy?.value || 'name';
        
        // Filter subjects
        filteredSubjects = allSubjects.filter(subject => {
            const matchesSearch = !searchTerm || 
                subject.name.includes(searchTerm) ||
                subject.description.includes(searchTerm) ||
                subject.teacher.includes(searchTerm);
            
            const matchesTeacher = !selectedTeacher || subject.teacher === selectedTeacher;
            
            return matchesSearch && matchesTeacher;
        });
        
        // Sort subjects
        filteredSubjects.sort((a, b) => {
            switch(sortOption) {
                case 'name':
                    return a.name.localeCompare(b.name);
                case 'name-desc':
                    return b.name.localeCompare(a.name);
                case 'date':
                    return new Date(b.date) - new Date(a.date);
                case 'date-desc':
                    return new Date(a.date) - new Date(b.date);
                case 'teacher':
                    return a.teacher.localeCompare(b.teacher);
                default:
                    return 0;
            }
        });
        
        updateDisplay();
    }
    
    function updateDisplay() {
        // Hide all subjects first
        allSubjects.forEach(subject => {
            if (subject.gridElement) subject.gridElement.style.display = 'none';
            if (subject.listElement) subject.listElement.style.display = 'none';
        });
        
        // Show filtered subjects in correct order
        const container = currentView === 'grid' ? subjectsGrid : subjectsList;
        if (container) {
            filteredSubjects.forEach(subject => {
                const element = currentView === 'grid' ? subject.gridElement : subject.listElement;
                if (element) {
                    element.style.display = '';
                    container.appendChild(element); // Reorder elements
                }
            });
        }
        
        // Update results count
        if (resultsCount) {
            resultsCount.textContent = filteredSubjects.length;
        }
        
        // Show/hide no results message
        if (noResultsMessage) {
            if (filteredSubjects.length === 0 && allSubjects.length > 0) {
                noResultsMessage.classList.remove('hidden');
                if (subjectsGrid) subjectsGrid.style.display = 'none';
                if (subjectsList) subjectsList.style.display = 'none';
            } else {
                noResultsMessage.classList.add('hidden');
                if (currentView === 'grid' && subjectsGrid) subjectsGrid.style.display = 'grid';
                if (currentView === 'list' && subjectsList) subjectsList.style.display = 'block';
            }
        }
        
        // Show/hide clear search button
        if (clearSearch && searchInput) {
            if (searchInput.value.length > 0) {
                clearSearch.classList.remove('hidden');
            } else {
                clearSearch.classList.add('hidden');
            }
        }
    }
    
    // Event listeners
    if (searchInput) {
        searchInput.addEventListener('input', filterAndSortSubjects);
    }
    
    if (clearSearch) {
        clearSearch.addEventListener('click', () => {
            searchInput.value = '';
            filterAndSortSubjects();
        });
    }
    
    if (teacherFilter) {
        teacherFilter.addEventListener('change', filterAndSortSubjects);
    }
    
    if (sortBy) {
        sortBy.addEventListener('change', filterAndSortSubjects);
    }
    
    if (resetFilters) {
        resetFilters.addEventListener('click', () => {
            if (searchInput) searchInput.value = '';
            if (teacherFilter) teacherFilter.value = '';
            if (sortBy) sortBy.value = 'name';
            filterAndSortSubjects();
        });
    }
    
    // View toggle
    if (gridView) {
        gridView.addEventListener('click', () => {
            currentView = 'grid';
            gridView.classList.remove('bg-gray-200', 'text-gray-600');
            gridView.classList.add('bg-indigo-500', 'text-white');
            listView.classList.remove('bg-indigo-500', 'text-white');
            listView.classList.add('bg-gray-200', 'text-gray-600');
            
            if (subjectsGrid) subjectsGrid.classList.remove('hidden');
            if (subjectsList) subjectsList.classList.add('hidden');
            updateDisplay();
        });
    }
    
    if (listView) {
        listView.addEventListener('click', () => {
            currentView = 'list';
            listView.classList.remove('bg-gray-200', 'text-gray-600');
            listView.classList.add('bg-indigo-500', 'text-white');
            gridView.classList.remove('bg-indigo-500', 'text-white');
            gridView.classList.add('bg-gray-200', 'text-gray-600');
            
            if (subjectsList) subjectsList.classList.remove('hidden');
            if (subjectsGrid) subjectsGrid.classList.add('hidden');
            updateDisplay();
        });
    }
    
    // Quick enrollment functionality (only for students)
    if (quickEnrollModal) {
        document.addEventListener('click', function(e) {
            if (e.target.matches('.quick-enroll-btn')) {
                const subjectId = e.target.dataset.subjectId;
                const subjectName = e.target.dataset.subjectName;
                
                quickEnrollText.textContent = `Enroll in "${subjectName}"? You'll gain immediate access to all topics and quizzes.`;
                confirmQuickEnroll.dataset.subjectId = subjectId;
                confirmQuickEnroll.dataset.subjectName = subjectName;
                quickEnrollModal.classList.remove('hidden');
            }
        });
        
        if (confirmQuickEnroll) {
            confirmQuickEnroll.addEventListener('click', function() {
                const subjectId = this.dataset.subjectId;
                const subjectName = this.dataset.subjectName;
                
                fetch(`/subject/${subjectId}/enroll`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    }
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        // Update enrollment badges and buttons
                        updateEnrollmentStatus(subjectId, true);
                        showMessage(data.message, 'success');
                    } else {
                        showMessage(data.message, 'error');
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    showMessage('An error occurred while enrolling.', 'error');
                });
                
                quickEnrollModal.classList.add('hidden');
            });
        }
        
        if (cancelQuickEnroll) {
            cancelQuickEnroll.addEventListener('click', () => {
                quickEnrollModal.classList.add('hidden');
            });
        }
        
        // Close modal on backdrop click
        quickEnrollModal.addEventListener('click', function(e) {
            if (e.target === this) {
                this.classList.add('hidden');
            }
        });
    }
    
    function updateEnrollmentStatus(subjectId, isEnrolled) {
        // Find all elements related to this subject
        const subjectCards = document.querySelectorAll(`[data-subject-id="${subjectId}"]`);
        
        subjectCards.forEach(card => {
            const badge = card.closest('.subject-card, .subject-card-list').querySelector('.enrollment-badge');
            const enrollBtn = card.closest('.subject-card, .subject-card-list').querySelector('.quick-enroll-btn');
            
            if (badge) {
                badge.className = isEnrolled ? 
                    'enrollment-badge ml-2 px-3 py-1 rounded-full text-xs font-semibold bg-green-100 text-green-700' :
                    'enrollment-badge ml-2 px-3 py-1 rounded-full text-xs font-semibold bg-orange-100 text-orange-700';
                badge.textContent = isEnrolled ? 'Enrolled' : 'Available';
            }
            
            if (enrollBtn) {
                enrollBtn.style.display = isEnrolled ? 'none' : 'inline-block';
            }
        });
    }
    
    function showMessage(message, type) {
        const messageDiv = document.createElement('div');
        messageDiv.className = `fixed top-4 right-4 z-50 px-6 py-3 rounded-xl shadow-2xl font-semibold ${
            type === 'success' ? 'bg-green-500 text-white' : 'bg-red-500 text-white'
        }`;
        messageDiv.textContent = message;
        
        document.body.appendChild(messageDiv);
        
        setTimeout(() => {
            messageDiv.remove();
        }, 4000);
    }
});