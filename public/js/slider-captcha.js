// public/js/slider-captcha.js
class SliderCaptcha {
    constructor(container, options = {}) {
      this.container = typeof container === 'string' ? document.querySelector(container) : container;
      this.options = Object.assign({
        successText: 'Verified!',
        failureText: 'Try again',
        sliderText: 'Slide to verify',
        successThreshold: 0.9, // How close to the end to consider success (0-1)
        randomOffset: true, // Whether to use a random success point
        successCallback: null,
        failureCallback: null
      }, options);
      
      this.isDragging = false;
      this.isVerified = false;
      this.startX = 0;
      this.currentX = 0;
      this.successPoint = this.options.randomOffset ? 
        (0.85 + Math.random() * 0.1) : // Random point between 85% and 95%
        this.options.successThreshold;
      
      this.init();
    }
    
    init() {
      // Create elements
      this.container.innerHTML = `
        <div class="slider-captcha-bg">
          <div class="slider-captcha-puzzle"></div>
          <div class="slider-captcha-text">${this.options.sliderText}</div>
          <div class="slider-captcha-handle">
            <i class="fas fa-arrow-right"></i>
          </div>
        </div>
      `;
      
      // Get references to elements
      this.bg = this.container.querySelector('.slider-captcha-bg');
      this.puzzle = this.container.querySelector('.slider-captcha-puzzle');
      this.handle = this.container.querySelector('.slider-captcha-handle');
      this.text = this.container.querySelector('.slider-captcha-text');
      
      // Calculate dimensions
      this.maxX = this.bg.clientWidth - this.handle.clientWidth;
      
      // Add event listeners
      this.handle.addEventListener('mousedown', this.startDrag.bind(this));
      this.handle.addEventListener('touchstart', this.startDrag.bind(this));
      document.addEventListener('mousemove', this.drag.bind(this));
      document.addEventListener('touchmove', this.drag.bind(this));
      document.addEventListener('mouseup', this.endDrag.bind(this));
      document.addEventListener('touchend', this.endDrag.bind(this));
      
      // Handle window resize
      window.addEventListener('resize', () => {
        this.maxX = this.bg.clientWidth - this.handle.clientWidth;
        if (this.isVerified) {
          this.handle.style.left = `${this.maxX}px`;
        }
      });
    }
    
    startDrag(e) {
      if (this.isVerified) return;
      
      this.isDragging = true;
      this.startX = e.type === 'touchstart' ? 
        e.touches[0].clientX : e.clientX;
      this.currentX = parseInt(this.handle.style.left || '0', 10);
      
      // Prevent default behavior for touch events
      if (e.type === 'touchstart') {
        e.preventDefault();
      }
      
      // Add active class
      this.handle.classList.add('active');
    }
    
    drag(e) {
      if (!this.isDragging || this.isVerified) return;
      
      const clientX = e.type === 'touchmove' ? 
        e.touches[0].clientX : e.clientX;
      let moveX = clientX - this.startX + this.currentX;
      
      // Constrain movement within bounds
      moveX = Math.max(0, Math.min(moveX, this.maxX));
      
      // Update position
      this.handle.style.left = `${moveX}px`;
      
      // Update puzzle background
      const percentage = moveX / this.maxX;
      this.puzzle.style.background = `linear-gradient(90deg, #f26523 0%, #f26523 ${percentage * 100}%, transparent ${percentage * 100}%)`;
      
      // Prevent default behavior for touch events
      if (e.type === 'touchmove') {
        e.preventDefault();
      }
    }
    
    endDrag() {
      if (!this.isDragging || this.isVerified) return;
      
      this.isDragging = false;
      this.handle.classList.remove('active');
      
      const currentPosition = parseInt(this.handle.style.left || '0', 10);
      const percentage = currentPosition / this.maxX;
      
      // Check if verification is successful
      if (percentage >= this.successPoint) {
        this.success();
      } else {
        this.failure();
      }
    }
    
    success() {
      this.isVerified = true;
      
      // Update UI
      this.container.classList.add('slider-captcha-success');
      this.container.classList.remove('slider-captcha-error');
      this.text.textContent = this.options.successText;
      this.handle.style.left = `${this.maxX}px`;
      this.puzzle.style.background = `linear-gradient(90deg, #4CAF50 0%, #4CAF50 100%, transparent 100%)`;
      this.puzzle.style.opacity = '0.2';
      
      // Call success callback if provided
      if (typeof this.options.successCallback === 'function') {
        this.options.successCallback();
      }
    }
    
    failure() {
      // Update UI
      this.container.classList.add('slider-captcha-error');
      this.text.textContent = this.options.failureText;
      
      // Reset after a delay
      setTimeout(() => {
        this.reset();
      }, 1000);
      
      // Call failure callback if provided
      if (typeof this.options.failureCallback === 'function') {
        this.options.failureCallback();
      }
    }
    
    reset() {
      this.isVerified = false;
      this.container.classList.remove('slider-captcha-success', 'slider-captcha-error');
      this.handle.style.left = '0';
      this.puzzle.style.background = 'linear-gradient(90deg, #f26523 0%, #f26523 0%, transparent 0%)';
      this.text.textContent = this.options.sliderText;
      
      // Generate a new success point if random offset is enabled
      if (this.options.randomOffset) {
        this.successPoint = 0.85 + Math.random() * 0.1;
      }
    }
    
    // Public method to check if captcha is verified
    isValid() {
      return this.isVerified;
    }
    
    // Public method to manually reset the captcha
    resetCaptcha() {
      this.reset();
    }
  }
  
  // Make it available globally
  window.SliderCaptcha = SliderCaptcha;
  