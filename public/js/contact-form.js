
document.addEventListener('DOMContentLoaded', function() {
    const contactForm = document.getElementById('contactForm');
    const contactFormStatus = document.getElementById('contactFormStatus');

    if (contactForm) {
        contactForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const name = document.getElementById('contactName').value;
            const email = document.getElementById('contactEmail').value;
            const phone = document.getElementById('contactPhone').value;
            const country = document.getElementById('contactCountry').value;
            const subject = document.getElementById('contactSubject').value;
            const message = document.getElementById('contactMessage').value;
            
            const formData = {
                name,
                email,
                phone,
                country,
                subject,
                message
            };

            fetch('/api/contact', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(formData)
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    contactFormStatus.textContent = 'Message sent successfully!';
                    contactFormStatus.className = 'form-status success';
                    contactForm.reset();
                } else {
                    contactFormStatus.textContent = data.message || 'An error occurred.';
                    contactFormStatus.className = 'form-status error';
                }
            })
            .catch(error => {
                console.error('Error:', error);
                contactFormStatus.textContent = 'An error occurred. Please try again.';
                contactFormStatus.className = 'form-status error';
            });
        });
    }
});
