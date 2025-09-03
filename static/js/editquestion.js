 document.addEventListener('DOMContentLoaded', function() {
        const questionTypeSelect = document.getElementById('questionType');
        const multipleChoiceDiv = document.getElementById('multipleChoiceOptions');
        const trueFalseDiv = document.getElementById('trueFalseOptions');
        const openEndedDiv = document.getElementById('openEndedOptions');
        
        function toggleQuestionOptions() {
            const selectedType = questionTypeSelect.value;
            
            // Hide all option divs
            multipleChoiceDiv.classList.add('hidden');
            trueFalseDiv.classList.add('hidden');
            openEndedDiv.classList.add('hidden');
            
            // Show relevant div based on selection
            switch(selectedType) {
                case 'multiple_choice':
                    multipleChoiceDiv.classList.remove('hidden');
                    break;
                case 'true_false':
                    trueFalseDiv.classList.remove('hidden');
                    break;
                case 'identification':
                case 'enumeration':
                    openEndedDiv.classList.remove('hidden');
                    break;
            }
        }
        
        questionTypeSelect.addEventListener('change', toggleQuestionOptions);
        
        // Auto-resize textarea
        const questionTextarea = document.querySelector('textarea[name="question_text"]');
        questionTextarea.addEventListener('input', function() {
            this.style.height = 'auto';
            this.style.height = Math.max(this.scrollHeight, 60) + 'px';
        });
        
        // Initial resize
        questionTextarea.style.height = Math.max(questionTextarea.scrollHeight, 60) + 'px';
        
        // Form validation
        document.getElementById('editQuestionForm').addEventListener('submit', function(e) {
            const questionType = questionTypeSelect.value;
            const questionText = questionTextarea.value.trim();
            
            if (!questionText) {
                alert('Please enter a question.');
                e.preventDefault();
                return;
            }
            
            if (questionType === 'multiple_choice') {
                const correctAnswer = document.querySelector('input[name="correct_answer"]:checked');
                const optionA = document.querySelector('input[name="option_a"]').value.trim();
                const optionB = document.querySelector('input[name="option_b"]').value.trim();
                
                if (!optionA || !optionB) {
                    alert('Please fill in at least the first two options.');
                    e.preventDefault();
                    return;
                }
                
                if (!correctAnswer) {
                    alert('Please select the correct answer.');
                    e.preventDefault();
                    return;
                }
            }
            
            if (questionType === 'true_false') {
                const tfAnswer = document.querySelector('input[name="tf_answer"]:checked');
                if (!tfAnswer) {
                    alert('Please select the correct answer.');
                    e.preventDefault();
                    return;
                }
            }
            
            if (questionType === 'identification' || questionType === 'enumeration') {
                const correctAnswers = document.querySelector('textarea[name="correct_answers"]').value.trim();
                if (!correctAnswers) {
                    alert('Please provide the correct answer(s).');
                    e.preventDefault();
                    return;
                }
            }
        });
    });