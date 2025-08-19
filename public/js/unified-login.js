// public/js/unified-login.js
document.addEventListener('DOMContentLoaded', function() {
    // Store credentials temporarily
    window.tempLoginCredentials = {};
    
    // Get login elements
    const loginForm = document.getElementById('loginForm');
    const loginStepOne = document.getElementById('loginStepOne');
    const loginStepTwo = document.getElementById('loginStepTwo');
    const loginModal = document.getElementById('loginModal');
    const loginBtn = document.getElementById('loginBtn');
    const loginModalClose = document.getElementById('loginModalClose');
    const signupBtn = document.getElementById('signupBtn');
    const requestAccountBtn = document.getElementById('requestAccountBtn');
    
    let loginCaptcha;
    
    // Open login modal
    if (loginBtn && loginModal) {
        loginBtn.addEventListener('click', function() {
            loginModal.style.display = 'block';
            document.body.style.overflow = 'hidden';
        });
    }
    
    // Close login modal
    if (loginModalClose && loginModal) {
        loginModalClose.addEventListener('click', function() {
            loginModal.style.display = 'none';
            document.body.style.overflow = '';
            resetLoginForm();
        });
    }
    
    // Open signup modal
    if (signupBtn) {
        signupBtn.addEventListener('click', function() {
            loginModal.style.display = 'none';
            const signupModal = document.getElementById('signupModal');
            if (signupModal) {
                signupModal.style.display = 'block';
            }
        });
    }
    
    // Open admin signup modal (request account)
    if (requestAccountBtn) {
        requestAccountBtn.addEventListener('click', function() {
            loginModal.style.display = 'none';
            const adminSignupModal = document.getElementById('adminSignupModal');
            if (adminSignupModal) {
                adminSignupModal.style.display = 'block';
            }
        });
    }
    
    // Login form submission
    if (loginForm) {
        loginForm.addEventListener('submit', async (event) => {
            event.preventDefault();
            
            const emailOrUsername = document.getElementById('loginEmail').value.trim();
            const password = document.getElementById('loginPassword').value;
            
            if (!emailOrUsername || !password) {
                showMessage('Please fill in all fields.', true);
                return;
            }
            
            // Disable the button and show loading state
            const submitBtn = loginForm.querySelector('button[type="submit"]');
            const originalText = submitBtn.textContent;
            submitBtn.disabled = true;
            submitBtn.textContent = 'Verifying...';
            
            try {
                // First try to verify as regular user
                let response = await fetch('/verify-credentials', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ 
                        username: emailOrUsername, 
                        password: password 
                    }),
                    credentials: 'same-origin'
                });
                
                let data = await response.json();
                let isAdmin = false;
                
                // If user verification fails, try admin verification
                if (!data.success) {
                    response = await fetch('/api/admin/verify-credentials', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ 
                            email: emailOrUsername, 
                            password: password 
                        }),
                        credentials: 'same-origin'
                    });
                    
                    data = await response.json();
                    isAdmin = true;
                }
                
                if (data.success) {
                    // Store credentials temporarily
                    window.tempLoginCredentials = { 
                        emailOrUsername, 
                        password, 
                        isAdmin,
                        email: data.email || emailOrUsername
                    };
                    
                    // Show CAPTCHA step
                    loginStepOne.classList.remove('active-step');
                    loginStepTwo.classList.add('active-step');
                    
                    // Initialize CAPTCHA
                    if (!loginCaptcha) {
                        loginCaptcha = new SliderCaptcha('#loginCaptchaContainer', {
                            successCallback: function() {
                                document.getElementById('captchaContinueBtn').disabled = false;
                            }
                        });
                    } else {
                        loginCaptcha.resetCaptcha();
                        document.getElementById('captchaContinueBtn').disabled = true;
                    }
                } else {
                    if (data.status === 'pending') {
                        // Show pending approval modal for admin accounts
                        loginModal.style.display = 'none';
                        const accountPendingModal = document.getElementById('accountPendingModal');
                        if (accountPendingModal) {
                            accountPendingModal.style.display = 'block';
                        }
                    } else {
                        // Display error message for invalid credentials
                        const errorMessage = document.createElement('div');
                        errorMessage.className = 'error-message';
                        errorMessage.textContent = data.message || 'Invalid credentials.';
                        errorMessage.style.color = 'red';
                        errorMessage.style.marginTop = '10px';
                        
                        // Remove any existing error messages
                        const existingError = loginForm.querySelector('.error-message');
                        if (existingError) {
                            existingError.remove();
                        }
                        
                        // Add the error message to the form
                        loginForm.appendChild(errorMessage);
                        
                        // Also show a popup message
                        showMessage(data.message || 'Invalid credentials.', true);
                    }
                }
            } catch (error) {
                console.error('Login verification error:', error);
                showMessage('An error occurred. Please try again later.', true);
            } finally {
                // Restore button state
                submitBtn.disabled = false;
                submitBtn.textContent = originalText;
            }
        });
    }
    
    // CAPTCHA step event listeners
    document.getElementById('captchaBackBtn')?.addEventListener('click', function() {
        loginStepTwo.classList.remove('active-step');
        loginStepOne.classList.add('active-step');
    });
    
    document.getElementById('captchaContinueBtn')?.addEventListener('click', function() {
        if (loginCaptcha && loginCaptcha.isValid()) {
            // Complete login after CAPTCHA verification
            completeLogin(
                window.tempLoginCredentials.emailOrUsername,
                window.tempLoginCredentials.password,
                window.tempLoginCredentials.isAdmin
            );
        } else {
            showMessage('Please complete the slider verification first.', true);
        }
    });
    
    // Function to complete login after CAPTCHA verification
    async function completeLogin(emailOrUsername, password, isAdmin) {
        try {
            // Show loading state
            const continueBtn = document.getElementById('captchaContinueBtn');
            const originalText = continueBtn.textContent;
            continueBtn.disabled = true;
            continueBtn.textContent = "Logging in...";
            
            let loginResponse;
            
            if (isAdmin) {
                // Admin login
                loginResponse = await fetch('/api/admin/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ 
                        email: emailOrUsername, 
                        password: password, 
                        captchaVerified: true
                    }),
                    credentials: 'same-origin'
                });
            } else {
                // User login
                loginResponse = await fetch('/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ 
                        username: emailOrUsername, 
                        password: password, 
                        captchaVerified: true
                    }),
                    credentials: 'same-origin'
                });
            }
            
            const loginData = await loginResponse.json();
            
            if (loginData.success) {
                if (isAdmin) {
                    // Redirect to admin dashboard
                    window.location.href = '/admin-dashboard';
                } else {
                    // Set login state in localStorage for regular users
                    localStorage.setItem('isLoggedIn', 'true');
                    
                    // Close the modal
                    if (loginModal) {
                        closeModal(loginModal);
                    }
                    
                    // Show success message
                    showMessage('Login successful!', false);
                    
                    // Update UI immediately
                    updateNavbarUI();
                    
                    // Clear temporary credentials
                    window.tempLoginCredentials = {};
                    
                    // Redirect or refresh page if needed
                    setTimeout(() => {
                        window.location.reload();
                    }, 1000);
                }
            } else {
                showMessage(loginData.message || 'Login failed. Please try again.', true);
                
                // Go back to first step
                loginStepTwo.classList.remove('active-step');
                loginStepOne.classList.add('active-step');
            }
        } catch (error) {
            console.error('Error completing login:', error);
            showMessage('An error occurred during login. Please try again.', true);
            
            // Go back to first step
            loginStepTwo.classList.remove('active-step');
            loginStepOne.classList.add('active-step');
        } finally {
            // Restore button state if needed
            const continueBtn = document.getElementById('captchaContinueBtn');
            if (continueBtn) {
                continueBtn.disabled = false;
                continueBtn.textContent = "Continue";
            }
        }
    }
    
    // Reset login form
    function resetLoginForm() {
        if (loginForm) loginForm.reset();
        if (loginStepOne) loginStepOne.classList.add('active-step');
        if (loginStepTwo) loginStepTwo.classList.remove('active-step');
        window.tempLoginCredentials = {};
        
        // Remove any error messages
        const existingError = loginForm?.querySelector('.error-message');
        if (existingError) {
            existingError.remove();
        }
    }
    
    // Close modal when clicking outside
    window.addEventListener('click', function(event) {
        if (event.target === loginModal) {
            loginModal.style.display = 'none';
            document.body.style.overflow = '';
            resetLoginForm();
        }
    });
    
    // Update navbar UI on page load
    updateNavbarUI();
});

// Helper function to show messages
function showMessage(message, isError) {
    const messageElement = document.createElement('div');
    messageElement.classList.add(isError ? 'error-popup' : 'success-popup');
    messageElement.textContent = message;
    messageElement.style.position = 'fixed';
    messageElement.style.top = '20px';
    messageElement.style.left = '50%';
    messageElement.style.transform = 'translateX(-50%)';
    messageElement.style.padding = '10px 20px';
    messageElement.style.borderRadius = '5px';
    messageElement.style.backgroundColor = isError ? '#ffdddd' : '#ddffdd';
    messageElement.style.color = isError ? '#ff0000' : '#00aa00';
    messageElement.style.boxShadow = '0 2px 5px rgba(0,0,0,0.2)';
    messageElement.style.zIndex = '10000';
    
    document.body.appendChild(messageElement);
    setTimeout(() => messageElement.remove(), 3000);
}

// Helper function to close modals
function closeModal(modal) {
    if (modal) {
        modal.style.display = 'none';
        document.body.style.overflow = '';
    }
}
