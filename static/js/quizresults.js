document.addEventListener('DOMContentLoaded', function() {
        // Animate score displays
        const scoreElements = document.querySelectorAll('[class*="score-"]');
        scoreElements.forEach((element, index) => {
            element.style.opacity = '0';
            element.style.transform = 'scale(0.8)';
            
            setTimeout(() => {
                element.style.transition = 'all 0.5s ease';
                element.style.opacity = '1';
                element.style.transform = 'scale(1)';
            }, index * 100);
        });

        // Add hover effects to cards
        const cards = document.querySelectorAll('.card-hover');
        cards.forEach(card => {
            card.addEventListener('mouseenter', function() {
                this.style.transform = 'translateY(-2px)';
            });
            
            card.addEventListener('mouseleave', function() {
                this.style.transform = 'translateY(0)';
            });
        });
    });