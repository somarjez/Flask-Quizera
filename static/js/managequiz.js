        let questionToDelete = null;
        let quizId = null;

        function toggleView(view) {
            const listView = document.getElementById('list-view');
            const gridView = document.getElementById('grid-view');
            const listBtn = document.getElementById('list-btn');
            const gridBtn = document.getElementById('grid-btn');

            if (view === 'list') {
                listView.classList.remove('hidden');
                gridView.classList.add('hidden');
                listBtn.classList.remove('bg-gray-300', 'text-gray-700');
                listBtn.classList.add('bg-blue-500', 'text-white');
                gridBtn.classList.remove('bg-blue-500', 'text-white');
                gridBtn.classList.add('bg-gray-300', 'text-gray-700');
            } else {
                listView.classList.add('hidden');
                gridView.classList.remove('hidden');
                gridBtn.classList.remove('bg-gray-300', 'text-gray-700');
                gridBtn.classList.add('bg-blue-500', 'text-white');
                listBtn.classList.remove('bg-blue-500', 'text-white');
                listBtn.classList.add('bg-gray-300', 'text-gray-700');
            }
        }

        function deleteQuestion(questionId, quiz_id) {
            questionToDelete = questionId;
            quizId = quiz_id;
            document.getElementById('deleteModal').classList.remove('hidden');
        }

        function closeDeleteModal() {
            document.getElementById('deleteModal').classList.add('hidden');
            questionToDelete = null;
            quizId = null;
        }

        function confirmDelete() {
            if (questionToDelete && quizId) {
                fetch(`/quiz/${quizId}/question/${questionToDelete}/delete`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Requested-With': 'XMLHttpRequest'
                    }
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        location.reload();
                    } else {
                        alert('Error deleting question: ' + data.message);
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    alert('Error deleting question');
                });
            }
            closeDeleteModal();
        }

        // Auto-hide flash messages
        document.addEventListener('DOMContentLoaded', function() {
            const flashMessages = document.querySelectorAll('.flash-message');
            flashMessages.forEach(message => {
                setTimeout(() => {
                    message.style.opacity = '0';
                    setTimeout(() => message.remove(), 300);
                }, 5000);
            });
        });