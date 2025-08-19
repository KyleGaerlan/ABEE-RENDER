document.addEventListener('DOMContentLoaded', function() {
    // Initialize tour carousel
    initTourCarousel();
    
    // Add event listeners for carousel controls
    document.getElementById('prevTour').addEventListener('click', () => navigateCarousel(-1));
    document.getElementById('nextTour').addEventListener('click', () => navigateCarousel(1));
});

let currentSlide = 0;
let totalSlides = 0;
let slidesPerView = 3;
let tours = [];

// Adjust slides per view based on screen size
function updateSlidesPerView() {
    if (window.innerWidth < 768) {
        slidesPerView = 1;
    } else if (window.innerWidth < 992) {
        slidesPerView = 2;
    } else {
        slidesPerView = 3;
    }
}

async function initTourCarousel() {
    updateSlidesPerView();
    await fetchTours();
    renderTours();
    
    // Add window resize listener
    window.addEventListener('resize', () => {
        const oldSlidesPerView = slidesPerView;
        updateSlidesPerView();
        
        if (oldSlidesPerView !== slidesPerView) {
            renderTours();
        }
    });
}

async function fetchTours() {
    try {
        const response = await fetch('/api/tours/featured');
        
        if (!response.ok) {
            throw new Error('Failed to fetch tours');
        }
        
        const data = await response.json();
        tours = data.tours;
        totalSlides = Math.ceil(tours.length / slidesPerView);
        
    } catch (error) {
        console.error('Error fetching tours:', error);
        document.getElementById('tourCarouselInner').innerHTML = 
            '<div class="error-message">Failed to load tours. Please try again later.</div>';
    }
}

function renderTours() {
    const carouselInner = document.getElementById('tourCarouselInner');
    const dotsContainer = document.getElementById('carouselDots');
    
    if (!tours || tours.length === 0) {
        carouselInner.innerHTML = '<div class="no-tours">No featured tours available at the moment.</div>';
        return;
    }
    
    carouselInner.innerHTML = '';
    dotsContainer.innerHTML = '';
    
    // Calculate total slides needed
    totalSlides = Math.ceil(tours.length / slidesPerView);
    
    // Create tour cards
    tours.forEach((tour, index) => {
        const tourCard = document.createElement('div');
        tourCard.className = 'tour-card';
        tourCard.innerHTML = `
            <img src="${tour.imageUrl}" alt="${tour.title}" class="tour-image">
            <div class="tour-info">
                <h3 class="tour-title">${tour.title}</h3>
                <div class="tour-destination">${tour.destination}</div>
                <div class="tour-meta">
                    <span>${tour.duration} ${tour.durationUnit}</span>
                    <span class="tour-price">₱${tour.price.toFixed(2)}</span>
                </div>
                <p class="tour-description">${tour.description.substring(0, 100)}${tour.description.length > 100 ? '...' : ''}</p>
                <a href="javascript:void(0);" class="view-tour-btn" onclick="showTourDetails('${tour._id}')">View Details</a>
            </div>
        `;
        carouselInner.appendChild(tourCard);
    });
    
    // Create dots for navigation
    for (let i = 0; i < totalSlides; i++) {
        const dot = document.createElement('div');
        dot.className = `carousel-dot ${i === currentSlide ? 'active' : ''}`;
        dot.addEventListener('click', () => goToSlide(i));
        dotsContainer.appendChild(dot);
    }
    
    // Set initial position
    updateCarouselPosition();
}

function navigateCarousel(direction) {
    currentSlide += direction;
    
    // Handle wrapping
    if (currentSlide < 0) {
        currentSlide = totalSlides - 1;
    } else if (currentSlide >= totalSlides) {
        currentSlide = 0;
    }
    
    updateCarouselPosition();
}

function goToSlide(slideIndex) {
    currentSlide = slideIndex;
    updateCarouselPosition();
}

function updateCarouselPosition() {
    const carouselInner = document.getElementById('tourCarouselInner');
    const dots = document.querySelectorAll('.carousel-dot');
    
    // Calculate the translation amount
    const translateX = -currentSlide * (100 / slidesPerView) * slidesPerView;
    carouselInner.style.transform = `translateX(${translateX}%)`;
    
    // Update active dot
    dots.forEach((dot, index) => {
        dot.classList.toggle('active', index === currentSlide);
    });
}

function showTourDetails(tourId) {
    const tour = tours.find(t => t._id === tourId);
    
    if (!tour) {
        console.error('Tour not found:', tourId);
        return;
    }
    
    // Create modal if it doesn't exist
    let modal = document.getElementById('tourDetailModal');
    if (!modal) {
        modal = document.createElement('div');
        modal.id = 'tourDetailModal';
        modal.className = 'tour-detail-modal';
        document.body.appendChild(modal);
    }
    
    // Populate modal content
    modal.innerHTML = `
        <div class="tour-detail-content">
            <div class="tour-detail-header">
                <img src="${tour.imageUrl}" alt="${tour.title}">
                <div class="tour-detail-header-overlay">
                    <h2>${tour.title}</h2>
                    <div class="tour-destination">${tour.destination}</div>
                </div>
            </div>
            <div class="tour-detail-body">
                <div class="tour-detail-meta">
                    <div class="tour-detail-price">₱${tour.price.toFixed(2)}</div>
                    <div class="tour-detail-duration">${tour.duration} ${tour.durationUnit}</div>
                </div>
                
                <div class="tour-detail-description">
                    ${tour.description}
                </div>
                
                <div class="tour-detail-section">
                    <h3>Highlights</h3>
                    <ul class="tour-detail-list">
                        ${tour.highlights.map(highlight => `<li>${highlight}</li>`).join('')}
                    </ul>
                </div>
                
                <div class="tour-detail-section">
                    <h3>Inclusions</h3>
                    <ul class="tour-detail-list">
                        ${tour.inclusions.map(inclusion => `<li>${inclusion}</li>`).join('')}
                    </ul>
                </div>
                
                <div class="tour-detail-section">
                    <h3>Exclusions</h3>
                    <ul class="tour-detail-list">
                        ${tour.exclusions.map(exclusion => `<li>${exclusion}</li>`).join('')}
                    </ul>
                </div>
                
                <div class="tour-detail-section">
                    <h3>Itinerary</h3>
                    <div class="tour-detail-itinerary">
                        ${tour.itinerary.map(day => `
                            <div class="itinerary-day">
                                <h4>Day ${day.day}: ${day.title}</h4>
                                <p>${day.description}</p>
                            </div>
                        `).join('')}
                    </div>
                </div>
                
                <div class="tour-detail-actions">
                    <button class="close-detail-btn" onclick="closeTourDetails()">Close</button>
                    <a href="/book-tour?tourId=${tour._id}" class="book-tour-btn" style="text-decoration:none">Book This Tour</a>
                </div>
            </div>
        </div>
    `;
    
    // Show modal
    modal.style.display = 'block';
    
    // Prevent body scrolling
    document.body.style.overflow = 'hidden';
}

function closeTourDetails() {
    const modal = document.getElementById('tourDetailModal');
    if (modal) {
        modal.style.display = 'none';
    }
    
    // Re-enable body scrolling
    document.body.style.overflow = '';
}

// Close modal when clicking outside of it
window.addEventListener('click', function(event) {
    const modal = document.getElementById('tourDetailModal');
    if (modal && event.target === modal) {
        closeTourDetails();
    }
});
function createTourCard(tour) {
    return `
        <div class="tour-card">
            ${tour.featured ? '<div class="featured-badge">Featured</div>' : ''}
            <img src="${tour.imageUrl}" alt="${tour.title}" class="tour-image">
            <div class="tour-content">
                <h3 class="tour-title">${tour.title}</h3>
                <div class="tour-destination">${tour.destination}</div>
                <div class="tour-duration">${tour.duration} ${tour.durationUnit}</div>
                <div class="tour-price">₱${tour.price.toLocaleString()}</div>
                <div class="tour-actions">
                    <a href="/tour/${tour._id}" class="btn-view-details">View Details</a>
                    <a href="/book-tour?id=${tour._id}" class="btn-book-now">Book Now</a>
                </div>
            </div>
        </div>
    `;
}
