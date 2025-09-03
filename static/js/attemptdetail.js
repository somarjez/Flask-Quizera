  document.addEventListener('DOMContentLoaded', function() {
        // Animate progress bar
        const progressBar = document.querySelector('[style*="width"]');
        if (progressBar) {
            progressBar.style.width = '0%';
            setTimeout(() => {
                progressBar.style.width = '{{ attempt.percentage }}%';
            }, 500);
        }
        
        // Add hover effects to question cards
        const questionCards = document.querySelectorAll('.question-correct, .question-incorrect');
        questionCards.forEach(card => {
            card.addEventListener('mouseenter', function() {
                this.style.transform = 'translateY(-2px)';
            });
            
            card.addEventListener('mouseleave', function() {
                this.style.transform = 'translateY(0)';
            });
        });
    });