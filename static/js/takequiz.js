    let timeRemaining = {{ quiz.time_limit }} * 60; // Convert minutes to seconds
    const timerDisplay = document.getElementById('timer-display');
    
    function updateTimer() {
        const minutes = Math.floor(timeRemaining / 60);
        const seconds = timeRemaining % 60;
        timerDisplay.textContent = `${minutes}:${seconds.toString().padStart(2, '0')}`;
        
        if (timeRemaining <= 0) {
            alert('Time is up! Your quiz will be automatically submitted.');
            submitQuiz();
        } else {
            timeRemaining--;
        }
    }
    
    // Update timer every second
    const timerInterval = setInterval(updateTimer, 1000);
    
    // Option selection styling
    document.querySelectorAll('input[type="radio"]').forEach(radio => {
        radio.addEventListener('change', function() {
            // Remove selected class from all options in this question
            const questionName = this.name;
            document.querySelectorAll(`input[name="${questionName}"]`).forEach(r => {
                r.closest('label').classList.remove('selected');
            });
            
            // Add selected class to chosen option
            this.closest('label').classList.add('selected');
        });
    });
    
    // Form submission
    const quizForm = document.getElementById('quiz-form');
    const submitModal = document.getElementById('submit-modal');
    const confirmSubmit = document.getElementById('confirm-submit');
    const cancelSubmit = document.getElementById('cancel-submit');
    
    // Show modal when form is submitted
    quizForm.addEventListener('submit', function(e) {
        e.preventDefault();
        submitModal.classList.remove('hidden');
        submitModal.classList.add('flex');
    });
    
    // Handle modal actions
    confirmSubmit.addEventListener('click', submitQuiz);
    
    cancelSubmit.addEventListener('click', function() {
        submitModal.classList.add('hidden');
        submitModal.classList.remove('flex');
    });
    
    function submitQuiz() {
        clearInterval(timerInterval);
        
        const formData = new FormData(quizForm);
        const answers = {};
        
        // Collect all answers
        for (let [key, value] of formData.entries()) {
            if (key.includes(',')) {
                // Handle enumeration (comma-separated values)
                answers[key] = value.split(',').map(v => v.trim());
            } else {
                answers[key] = value;
            }
        }
        
        // Submit to server
        fetch(`/quiz/{{ quiz.id }}/submit`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ answers: answers })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                alert(`Quiz submitted successfully! Your score: ${data.score}/${data.total} (${data.percentage}%)`);
                window.location.href = `/quiz-attempt/${data.attempt_id}`;
            } else {
                alert('Error submitting quiz: ' + data.message);
            }
        })
        .catch(error => {
            console.error('Error:', error);
            alert('Error submitting quiz. Please try again.');
        });
    }
    
    // Warn user before leaving page
    window.addEventListener('beforeunload', function(e) {
        e.preventDefault();
        e.returnValue = 'Are you sure you want to leave? Your progress will be lost.';
    });