document.addEventListener('DOMContentLoaded', function() {
    const slides = document.querySelectorAll('.bg-slide');
    let currentSlide = 0;
    
    function nextSlide() {
        slides[currentSlide].classList.remove('active');
        currentSlide = (currentSlide + 1) % slides.length;
        slides[currentSlide].classList.add('active');
    }
    const textItems = document.querySelectorAll('.rotate-item');
    let currentText = 0;
    
    function nextText() {
        textItems[currentText].classList.remove('active');
        currentText = (currentText + 1) % textItems.length;
        textItems[currentText].classList.add('active');
        adjustRotatingTextWidth();
    }
    function adjustRotatingTextWidth() {
        const container = document.querySelector('.rotating-text');
        const activeItem = document.querySelector('.rotate-item.active');
        
        if (container && activeItem) {
            container.style.width = activeItem.offsetWidth + 'px';
        }
    }
    adjustRotatingTextWidth();
    const observer = new MutationObserver(function(mutations) {
        mutations.forEach(function(mutation) {
            if (mutation.attributeName === 'class') {
                adjustRotatingTextWidth();
            }
        });
    });
    textItems.forEach(function(item) {
        observer.observe(item, { attributes: true });
    });
    window.addEventListener('resize', adjustRotatingTextWidth);
    setInterval(nextSlide, 5000);
    setInterval(nextText, 5000);
});
