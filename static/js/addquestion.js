 class CSVUploader {
        constructor() {
            this.csvData = [];
            this.validQuestions = [];
            this.initializeEventListeners();
        }

        initializeEventListeners() {
            const csvDropZone = document.getElementById('csvDropZone');
            const csvFileInput = document.getElementById('csvFile');
            const browseBtn = document.getElementById('browseBtn');

            // File input events
            browseBtn.addEventListener('click', () => csvFileInput.click());
            csvFileInput.addEventListener('change', (e) => this.handleFileSelect(e));

            // Drag and drop events
            csvDropZone.addEventListener('dragover', (e) => this.handleDragOver(e));
            csvDropZone.addEventListener('dragleave', (e) => this.handleDragLeave(e));
            csvDropZone.addEventListener('drop', (e) => this.handleDrop(e));
            csvDropZone.addEventListener('click', () => csvFileInput.click());

            // Button events
            document.getElementById('downloadSample').addEventListener('click', () => this.downloadSampleCSV());
            document.getElementById('clearCsv').addEventListener('click', () => this.clearCSV());
        }

        handleDragOver(e) {
            e.preventDefault();
            e.stopPropagation();
            const dropZone = document.getElementById('csvDropZone');
            dropZone.classList.add('border-purple-400', 'bg-purple-50');
        }

        handleDragLeave(e) {
            e.preventDefault();
            e.stopPropagation();
            const dropZone = document.getElementById('csvDropZone');
            dropZone.classList.remove('border-purple-400', 'bg-purple-50');
        }

        handleDrop(e) {
            e.preventDefault();
            e.stopPropagation();
            const dropZone = document.getElementById('csvDropZone');
            dropZone.classList.remove('border-purple-400', 'bg-purple-50');
            
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                this.handleFile(files[0]);
            }
        }

        handleFileSelect(e) {
            const files = e.target.files;
            if (files.length > 0) {
                this.handleFile(files[0]);
            }
        }

        handleFile(file) {
            const validationResult = this.validateFile(file);
            if (!validationResult.valid) {
                this.showError([validationResult.error]);
                return;
            }

            this.showProgress();
            this.readFile(file);
        }

        validateFile(file) {
            if (!file.name.toLowerCase().endsWith('.csv')) {
                return { valid: false, error: 'Please upload a CSV file (.csv extension required)' };
            }

            const maxSize = 10 * 1024 * 1024; // 10MB
            if (file.size > maxSize) {
                return { valid: false, error: 'File size too large. Maximum size is 10MB.' };
            }

            if (file.size === 0) {
                return { valid: false, error: 'File is empty. Please upload a valid CSV file.' };
            }

            return { valid: true };
        }

        readFile(file) {
            const reader = new FileReader();
            
            reader.onload = (e) => {
                try {
                    const text = e.target.result;
                    this.parseCSV(text);
                } catch (error) {
                    this.hideProgress();
                    this.showError(['Error reading file: ' + error.message]);
                }
            };

            reader.onerror = () => {
                this.hideProgress();
                this.showError(['Error reading file. Please try again.']);
            };

            reader.readAsText(file);
        }

        parseCSV(text) {
            try {
                const lines = text.split(/\r?\n/).filter(line => line.trim());
                
                if (lines.length < 2) {
                    throw new Error('CSV file must contain at least a header row and one data row');
                }

                const header = this.parseCSVLine(lines[0]);
                const expectedHeaders = ['question_type', 'question_text', 'choices', 'answers', 'points'];
                
                if (!this.validateHeaders(header, expectedHeaders)) {
                    throw new Error(`Invalid headers. Expected: ${expectedHeaders.join(', ')}`);
                }

                const questions = [];
                const errors = [];

                for (let i = 1; i < lines.length; i++) {
                    try {
                        const rowData = this.parseCSVLine(lines[i]);
                        if (rowData.length === 0) continue;
                        
                        const question = this.parseQuestionRow(rowData, i + 1);
                        if (question) {
                            questions.push(question);
                        }
                    } catch (error) {
                        errors.push(`Row ${i + 1}: ${error.message}`);
                    }
                }

                this.hideProgress();

                if (errors.length > 0 && questions.length === 0) {
                    this.showError(errors);
                    return;
                }

                this.csvData = questions;
                this.displayPreview(questions, errors);

            } catch (error) {
                this.hideProgress();
                this.showError([error.message]);
            }
        }

        parseCSVLine(line) {
            const result = [];
            let current = '';
            let inQuotes = false;
            let i = 0;

            while (i < line.length) {
                const char = line[i];
                
                if (char === '"') {
                    if (inQuotes && line[i + 1] === '"') {
                        current += '"';
                        i += 2;
                    } else {
                        inQuotes = !inQuotes;
                        i++;
                    }
                } else if (char === ',' && !inQuotes) {
                    result.push(current.trim());
                    current = '';
                    i++;
                } else {
                    current += char;
                    i++;
                }
            }
            
            result.push(current.trim());
            return result;
        }

        validateHeaders(headers, expected) {
            if (headers.length !== expected.length) return false;
            
            for (let i = 0; i < expected.length; i++) {
                if (headers[i].toLowerCase().trim() !== expected[i]) {
                    return false;
                }
            }
            return true;
        }

        parseQuestionRow(rowData, rowNumber) {
            if (rowData.length < 5) {
                throw new Error('Insufficient columns (expected 5: question_type, question_text, choices, answers, points)');
            }

            const [questionType, questionText, choices, answers, pointsStr] = rowData;

            const validTypes = ['multiple_choice', 'true_false', 'identification', 'enumeration'];
            if (!validTypes.includes(questionType.toLowerCase().trim())) {
                throw new Error(`Invalid question type: ${questionType}. Valid types: ${validTypes.join(', ')}`);
            }

            if (!questionText.trim()) {
                throw new Error('Question text cannot be empty');
            }

            const points = parseInt(pointsStr);
            if (isNaN(points) || points < 1 || points > 10) {
                throw new Error('Points must be a number between 1 and 10');
            }

            const type = questionType.toLowerCase().trim();
            
            // Validate based on question type
            if (type === 'multiple_choice') {
                if (!choices.trim()) {
                    throw new Error('Multiple choice questions must have choices');
                }
                if (!answers.trim()) {
                    throw new Error('Multiple choice questions must have a correct answer (A, B, C, or D)');
                }
                
                const choicesArray = choices.split('|').map(c => c.trim()).filter(c => c);
                if (choicesArray.length < 2) {
                    throw new Error('Multiple choice questions must have at least 2 options');
                }
                
                const correctAnswer = answers.trim().toUpperCase();
                if (!['A', 'B', 'C', 'D'].includes(correctAnswer)) {
                    throw new Error('Multiple choice answer must be A, B, C, or D');
                }
                
                return {
                    type: type,
                    question: questionText.trim(),
                    choicesArray: choicesArray,
                    correct_answer: correctAnswer,
                    points: points,
                    rowNumber: rowNumber
                };
            }
            
            if (type === 'true_false') {
                if (!answers.trim()) {
                    throw new Error('True/false questions must have an answer');
                }
                
                const answer = answers.trim().toLowerCase();
                if (!['true', 'false'].includes(answer)) {
                    throw new Error('True/false answer must be "true" or "false"');
                }
                
                return {
                    type: type,
                    question: questionText.trim(),
                    correct_answer: answer === 'true',
                    points: points,
                    rowNumber: rowNumber
                };
            }
            
            if (type === 'identification' || type === 'enumeration') {
                if (!answers.trim()) {
                    throw new Error(`${type} questions must have answers`);
                }
                
                const answersArray = answers.split('|').map(a => a.trim()).filter(a => a);
                if (answersArray.length === 0) {
                    throw new Error('At least one answer must be provided');
                }
                
                return {
                    type: type,
                    question: questionText.trim(),
                    answersArray: answersArray,
                    points: points,
                    rowNumber: rowNumber
                };
            }

            throw new Error('Invalid question type');
        }

        displayPreview(questions, errors = []) {
            const previewDiv = document.getElementById('csvPreview');
            const contentDiv = document.getElementById('csvPreviewContent');
            const countSpan = document.getElementById('csvQuestionCount');
            const validCountSpan = document.getElementById('validQuestionCount');
            const importBtn = document.getElementById('importCsvQuestions');
            const clearBtn = document.getElementById('clearCsv');

            countSpan.textContent = questions.length;
            validCountSpan.textContent = `${questions.length} valid questions found`;

            if (errors.length > 0) {
                this.showError(errors);
            } else {
                this.hideError();
            }

            if (questions.length > 0) {
                let previewHTML = '';
                questions.forEach((q, index) => {
                    const typeLabel = {
                        'multiple_choice': 'Multiple Choice',
                        'true_false': 'True/False',
                        'identification': 'Short Answer',
                        'enumeration': 'Paragraph'
                    }[q.type] || q.type;

                    let answerDisplay = '';
                    if (q.type === 'multiple_choice') {
                        answerDisplay = `Options: ${q.choicesArray.join(', ')} | Correct: ${q.correct_answer}`;
                    } else if (q.type === 'true_false') {
                        answerDisplay = `Answer: ${q.correct_answer ? 'True' : 'False'}`;
                    } else if (q.answersArray) {
                        answerDisplay = `Answers: ${q.answersArray.join(', ')}`;
                    }

                    previewHTML += `
                        <div class="p-4 border-b border-gray-200 ${index % 2 === 0 ? 'bg-gray-50' : 'bg-white'}">
                            <div class="flex items-start space-x-3">
                                <span class="bg-purple-100 text-purple-700 w-8 h-8 rounded-full flex items-center justify-center text-sm font-medium">${index + 1}</span>
                                <div class="flex-1">
                                    <div class="flex items-center space-x-2 mb-2">
                                        <span class="text-xs bg-blue-100 text-blue-800 px-2 py-1 rounded font-medium">${typeLabel}</span>
                                        <span class="text-xs text-gray-500">${q.points} point${q.points !== 1 ? 's' : ''}</span>
                                    </div>
                                    <p class="text-sm font-medium text-gray-900 mb-2">${this.escapeHtml(q.question)}</p>
                                    <div class="text-xs text-gray-600">
                                        ${answerDisplay}
                                    </div>
                                </div>
                            </div>
                        </div>
                    `;
                });
                
                contentDiv.innerHTML = previewHTML;
                previewDiv.classList.remove('hidden');
                importBtn.disabled = false;
                clearBtn.disabled = false;
            } else {
                previewDiv.classList.add('hidden');
                importBtn.disabled = true;
                clearBtn.disabled = true;
            }
        }

        escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        showProgress() {
            const progressDiv = document.getElementById('uploadProgress');
            const progressBar = document.getElementById('progressBar');
            const progressText = document.getElementById('progressText');
            
            progressDiv.classList.remove('hidden');
            
            let progress = 0;
            const interval = setInterval(() => {
                progress += Math.random() * 30;
                if (progress > 90) progress = 90;
                progressBar.style.width = progress + '%';
                
                if (progress > 50) {
                    progressText.textContent = 'Processing CSV...';
                }
            }, 100);

            this.progressInterval = interval;
        }

        hideProgress() {
            const progressDiv = document.getElementById('uploadProgress');
            const progressBar = document.getElementById('progressBar');
            
            if (this.progressInterval) {
                clearInterval(this.progressInterval);
            }
            
            progressBar.style.width = '100%';
            setTimeout(() => {
                progressDiv.classList.add('hidden');
                progressBar.style.width = '0%';
            }, 500);
        }

        showError(errors) {
            const errorDiv = document.getElementById('errorMessages');
            const errorList = document.getElementById('errorList');
            
            errorList.innerHTML = '';
            errors.forEach(error => {
                const li = document.createElement('li');
                li.textContent = error;
                errorList.appendChild(li);
            });
            
            errorDiv.classList.remove('hidden');
        }

        hideError() {
            const errorDiv = document.getElementById('errorMessages');
            errorDiv.classList.add('hidden');
        }

        downloadSampleCSV() {
            const sampleData = [
                ['question_type', 'question_text', 'choices', 'answers', 'points'],
                ['multiple_choice', 'What is 2 + 2?', '2|3|4|5', 'C', '1'],
                ['true_false', 'The sky is blue', '', 'true', '1'],
                ['identification', 'What is the capital of France?', '', 'Paris|paris', '2'],
                ['enumeration', 'Explain photosynthesis in your own words', '', 'Process by which plants convert light energy into chemical energy', '3']
            ];

            const csvContent = sampleData.map(row => 
                row.map(field => 
                    field.includes(',') || field.includes('"') ? `"${field.replace(/"/g, '""')}"` : field
                ).join(',')
            ).join('\n');

            const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
            const link = document.createElement('a');
            link.href = URL.createObjectURL(blob);
            link.download = 'quiz_questions_template.csv';
            link.style.display = 'none';
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        }

        clearCSV() {
            this.csvData = [];
            this.validQuestions = [];
            
            document.getElementById('csvFile').value = '';
            document.getElementById('csvPreview').classList.add('hidden');
            document.getElementById('csvQuestionCount').textContent = '0';
            document.getElementById('importCsvQuestions').disabled = true;
            document.getElementById('clearCsv').disabled = true;
            this.hideError();
        }
    }

    // Main application logic
    let csvUploader;
    let bulkQuestionCount = 1;

    document.addEventListener('DOMContentLoaded', function() {
        // Initialize CSV uploader
        csvUploader = new CSVUploader();

        // Method switching
        const methodBtns = document.querySelectorAll('.method-btn');
        const methodContents = document.querySelectorAll('.method-content');

        methodBtns.forEach(btn => {
            btn.addEventListener('click', function() {
                const method = this.id.replace('MethodBtn', '');
                
                methodBtns.forEach(b => {
                    b.classList.remove('active', 'bg-purple-100', 'text-purple-700', 'border-purple-200');
                    b.classList.add('text-gray-600', 'hover:bg-gray-100', 'border-gray-200');
                });
                this.classList.add('active', 'bg-purple-100', 'text-purple-700', 'border-purple-200');
                this.classList.remove('text-gray-600', 'hover:bg-gray-100', 'border-gray-200');
                
                methodContents.forEach(content => content.classList.add('hidden'));
                document.getElementById(method + 'Method').classList.remove('hidden');
            });
        });

        // Single question functionality
        const questionTypeSelect = document.getElementById('questionType');
        const multipleChoiceDiv = document.getElementById('multipleChoiceOptions');
        const trueFalseDiv = document.getElementById('trueFalseOptions');
        const openEndedDiv = document.getElementById('openEndedOptions');
        
        function toggleQuestionOptions() {
            const selectedType = questionTypeSelect.value;
            
            multipleChoiceDiv.classList.add('hidden');
            trueFalseDiv.classList.add('hidden');
            openEndedDiv.classList.add('hidden');
            
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

        // Bulk questions functionality
        function updateBulkQuestionOptions(questionDiv) {
            const select = questionDiv.querySelector('.bulk-type-select');
            const mcOptions = questionDiv.querySelector('.bulk-mc-options');
            const tfOptions = questionDiv.querySelector('.bulk-tf-options');
            const openOptions = questionDiv.querySelector('.bulk-open-options');
            
            function toggleOptions() {
                const selectedType = select.value;
                
                mcOptions.classList.add('hidden');
                tfOptions.classList.add('hidden');
                openOptions.classList.add('hidden');
                
                switch(selectedType) {
                    case 'multiple_choice':
                        mcOptions.classList.remove('hidden');
                        break;
                    case 'true_false':
                        tfOptions.classList.remove('hidden');
                        break;
                    case 'identification':
                    case 'enumeration':
                        openOptions.classList.remove('hidden');
                        break;
                }
            }
            
            select.addEventListener('change', toggleOptions);
        }

        // Initialize bulk question options for first question
        updateBulkQuestionOptions(document.querySelector('.bulk-question'));

        document.getElementById('addBulkQuestion').addEventListener('click', function() {
            bulkQuestionCount++;
            const bulkQuestionsDiv = document.getElementById('bulkQuestions');
            const newQuestion = document.createElement('div');
            newQuestion.className = 'bulk-question mb-6 p-4 border border-gray-200 rounded-lg';
            newQuestion.innerHTML = `
                <div class="flex items-start space-x-4 mb-4">
                    <span class="question-number bg-purple-100 text-purple-700 w-8 h-8 rounded-full flex items-center justify-center text-sm font-medium">${bulkQuestionCount}</span>
                    <div class="flex-1">
                        <select name="bulk_question_type[]" class="bulk-type-select bg-gray-50 border border-gray-200 rounded-md px-3 py-2 text-sm mb-3" required>
                            <option value="">Question Type</option>
                            <option value="multiple_choice">Multiple choice</option>
                            <option value="true_false">True/False</option>
                            <option value="identification">Short answer</option>
                            <option value="enumeration">Paragraph</option>
                        </select>
                        <textarea name="bulk_question_text[]" placeholder="Question text" class="w-full border border-gray-200 rounded-md p-3 text-sm" rows="2" required></textarea>
                        
                        <!-- Multiple Choice Options -->
                        <div class="bulk-mc-options hidden mt-3">
                            <label class="text-sm text-gray-600 mb-2 block">Multiple Choice Options:</label>
                            <div class="space-y-2 mb-3">
                                <input type="text" name="bulk_option_a[]" placeholder="Option A" class="w-full border border-gray-200 rounded px-3 py-2 text-sm">
                                <input type="text" name="bulk_option_b[]" placeholder="Option B" class="w-full border border-gray-200 rounded px-3 py-2 text-sm">
                                <input type="text" name="bulk_option_c[]" placeholder="Option C" class="w-full border border-gray-200 rounded px-3 py-2 text-sm">
                                <input type="text" name="bulk_option_d[]" placeholder="Option D" class="w-full border border-gray-200 rounded px-3 py-2 text-sm">
                            </div>
                            <select name="bulk_correct_answer[]" class="border border-gray-200 rounded px-3 py-2 text-sm">
                                <option value="A">Correct Answer: A</option>
                                <option value="B">Correct Answer: B</option>
                                <option value="C">Correct Answer: C</option>
                                <option value="D">Correct Answer: D</option>
                            </select>
                        </div>

                        <!-- True/False Options -->
                        <div class="bulk-tf-options hidden mt-3">
                            <label class="text-sm text-gray-600 mb-2 block">Correct Answer:</label>
                            <select name="bulk_tf_answer[]" class="border border-gray-200 rounded px-3 py-2 text-sm">
                                <option value="true">True</option>
                                <option value="false">False</option>
                            </select>
                        </div>

                        <!-- Open Ended Options -->
                        <div class="bulk-open-options hidden mt-3">
                            <label class="text-sm text-gray-600 mb-2 block">Correct Answers (separated by commas):</label>
                            <textarea name="bulk_answers[]" placeholder="Enter acceptable answers separated by commas" class="w-full border border-gray-200 rounded-md p-3 text-sm bg-gray-50" rows="2"></textarea>
                        </div>
                        
                        <div class="mt-3 flex items-center space-x-4">
                            <div class="flex items-center space-x-2">
                                <label class="text-sm text-gray-600">Points:</label>
                                <input type="number" name="bulk_points[]" value="1" min="1" max="10" class="w-16 px-2 py-1 border border-gray-200 rounded text-sm">
                            </div>
                            <button type="button" class="remove-question text-red-600 hover:text-red-800 text-sm">
                                <i class="fas fa-trash mr-1"></i>Remove
                            </button>
                        </div>
                    </div>
                </div>
            `;
            bulkQuestionsDiv.appendChild(newQuestion);
            updateBulkQuestionOptions(newQuestion);
            updateRemoveButtons();
        });

        function updateRemoveButtons() {
            const removeButtons = document.querySelectorAll('.remove-question');
            const questions = document.querySelectorAll('.bulk-question');
            
            removeButtons.forEach((btn, index) => {
                if (questions.length > 1) {
                    btn.style.display = 'inline-block';
                    btn.onclick = function() {
                        this.closest('.bulk-question').remove();
                        updateQuestionNumbers();
                        updateRemoveButtons();
                    };
                } else {
                    btn.style.display = 'none';
                }
            });
        }

        function updateQuestionNumbers() {
            const questions = document.querySelectorAll('.bulk-question');
            questions.forEach((question, index) => {
                const numberSpan = question.querySelector('.question-number');
                numberSpan.textContent = index + 1;
            });
            bulkQuestionCount = questions.length;
        }

        // Enhanced CSV import functionality
        document.getElementById('importCsvQuestions').addEventListener('click', async function() {
            if (csvUploader.csvData.length === 0) {
                csvUploader.showError(['No questions to import. Please upload a CSV file first.']);
                return;
            }

            const importBtn = this;
            const originalText = importBtn.textContent;
            
            importBtn.disabled = true;
            importBtn.textContent = 'Importing...';

            try {
                const response = await fetch('{{ url_for("add_question", quiz_id=quiz_id) }}', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        method: 'csv',
                        questions: csvUploader.csvData
                    })
                });

                const result = await response.json();

                if (result.success) {
                    alert(`Successfully imported ${csvUploader.csvData.length} questions!`);
                    csvUploader.clearCSV();
                    window.location.href = '{{ url_for("manage_quiz", quiz_id=quiz_id) }}';
                } else {
                    throw new Error(result.message || 'Import failed');
                }
            } catch (error) {
                console.error('Import error:', error);
                csvUploader.showError(['Import failed: ' + error.message]);
            } finally {
                importBtn.disabled = false;
                importBtn.textContent = originalText;
            }
        });

        // Form submissions
        document.getElementById('singleQuestionForm').addEventListener('submit', function(e) {
            const questionType = questionTypeSelect.value;
            const questionText = document.querySelector('textarea[name="question_text"]').value.trim();
            
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

        document.getElementById('saveBulkQuestions').addEventListener('click', function() {
            const questions = document.querySelectorAll('.bulk-question');
            const questionsData = [];
            
            let valid = true;
            questions.forEach((question, index) => {
                const type = question.querySelector('select[name="bulk_question_type[]"]').value;
                const text = question.querySelector('textarea[name="bulk_question_text[]"]').value.trim();
                const points = question.querySelector('input[name="bulk_points[]"]').value;
                
                if (!type || !text) {
                    valid = false;
                    return;
                }
                
                const questionData = {
                    type: type,
                    text: text,
                    points: parseInt(points) || 1
                };

                if (type === 'multiple_choice') {
                    const optionA = question.querySelector('input[name="bulk_option_a[]"]').value.trim();
                    const optionB = question.querySelector('input[name="bulk_option_b[]"]').value.trim();
                    const optionC = question.querySelector('input[name="bulk_option_c[]"]').value.trim();
                    const optionD = question.querySelector('input[name="bulk_option_d[]"]').value.trim();
                    const correctAnswer = question.querySelector('select[name="bulk_correct_answer[]"]').value;
                    
                    if (!optionA || !optionB) {
                        valid = false;
                        return;
                    }
                    
                    questionData.options = [optionA, optionB, optionC, optionD];
                    questionData.correct_answer = correctAnswer;
                } else if (type === 'true_false') {
                    const tfAnswer = question.querySelector('select[name="bulk_tf_answer[]"]').value;
                    questionData.correct_answer = tfAnswer === 'true';
                } else if (type === 'identification' || type === 'enumeration') {
                    const answers = question.querySelector('textarea[name="bulk_answers[]"]').value.trim();
                    if (!answers) {
                        valid = false;
                        return;
                    }
                    questionData.correct_answers = answers.split(',').map(a => a.trim()).filter(a => a);
                }
                
                questionsData.push(questionData);
            });
            
            if (!valid) {
                alert('Please fill in all required fields for each question.');
                return;
            }
            
            fetch('{{ url_for("add_question", quiz_id=quiz_id) }}', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    method: 'bulk',
                    questions: questionsData
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    window.location.href = '{{ url_for("manage_quiz", quiz_id=quiz_id) }}';
                } else {
                    alert('Error adding questions: ' + data.message);
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('Error adding questions. Please try again.');
            });
        });

        // Auto-resize textarea
        const questionTextarea = document.querySelector('textarea[name="question_text"]');
        if (questionTextarea) {
            questionTextarea.addEventListener('input', function() {
                this.style.height = 'auto';
                this.style.height = Math.max(this.scrollHeight, 60) + 'px';
            });
        }
    });