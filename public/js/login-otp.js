// public/js/login-otp.js (modified version)
document.addEventListener('DOMContentLoaded', function() {
    // Store user credentials temporarily
    window.tempLoginCredentials = {};
    
    // Get login elements
    const loginForm = document.getElementById('loginForm');
    const loginStepOne = document.getElementById('loginStepOne');
    
    // Create CAPTCHA step
    const loginStepCaptcha = document.createElement('div');
    loginStepCaptcha.id = 'loginStepCaptcha';
    loginStepCaptcha.className = 'login-step';
    loginStepCaptcha.innerHTML = `
        <h3>Security Verification</h3>
        <p>Please slide the handle to verify you're human.</p>
        
        <div id="loginCaptchaContainer" class="slider-captcha-container"></div>
        
        <div class="verification-actions">
            <button type="button" id="captchaBackBtn" class="btn secondary-btn">Back</button>
            <button type="button" id="captchaContinueBtn" class="btn primary-btn" disabled>Continue</button>
        </div>
    `;
    
    // Insert CAPTCHA step after login step one
    if (loginStepOne && loginStepOne.parentNode) {
        loginStepOne.parentNode.insertBefore(loginStepCaptcha, loginStepOne.nextSibling);
    }
    
    let loginCaptcha;
    
    if (loginForm) {
        loginForm.addEventListener('submit', async (event) => {
            event.preventDefault();
            
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            
            if (!username || !password) {
                showMessage('Please fill in all fields.', true);
                return;
            }
            
            // Disable the button and show loading state
            const submitBtn = loginForm.querySelector('button[type="submit"]');
            const originalText = submitBtn.textContent;
            submitBtn.disabled = true;
            submitBtn.textContent = 'Verifying...';
            
            try {
                // First verify credentials without completing login
                const response = await fetch('/verify-credentials', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password }),
                    credentials: 'same-origin'
                });
                
                const data = await response.json();
                
                if (data.success) {
                    // Store credentials temporarily
                    window.tempLoginCredentials = { username, password, email: data.email };
                    
                    // Show CAPTCHA step
                    loginStepOne.classList.remove('active-step');
                    loginStepCaptcha.classList.add('active-step');
                    
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
                    // Display error message for invalid credentials
                    const errorMessage = document.createElement('div');
                    errorMessage.className = 'error-message';
                    errorMessage.textContent = data.message || 'Invalid username or password.';
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
                    showMessage(data.message || 'Invalid username or password.', true);
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
        loginStepCaptcha.classList.remove('active-step');
        loginStepOne.classList.add('active-step');
    });
    
    document.getElementById('captchaContinueBtn')?.addEventListener('click', function() {
        if (loginCaptcha && loginCaptcha.isValid()) {
            // Complete login directly after CAPTCHA verification
            completeLogin(window.tempLoginCredentials.username, window.tempLoginCredentials.password);
        } else {
            showMessage('Please complete the slider verification first.', true);
        }
    });
    
    // Function to complete login after CAPTCHA verification
    async function completeLogin(username, password) {
        try {
            // Show loading state
            const continueBtn = document.getElementById('captchaContinueBtn');
            const originalText = continueBtn.textContent;
            continueBtn.disabled = true;
            continueBtn.textContent = "Logging in...";
            
            // Complete login
            const loginResponse = await fetch('/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    username: username, 
                    password: password, 
                    captchaVerified: true
                }),
                credentials: 'same-origin'
            });
            
            const loginData = await loginResponse.json();
            
            if (loginData.success) {
                // Set login state in localStorage
                localStorage.setItem('isLoggedIn', 'true');
                
                // Close the modal
                const loginModal = document.getElementById('loginModal');
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
            } else {
                showMessage(loginData.message || 'Login failed. Please try again.', true);
                
                // Go back to first step
                loginStepCaptcha.classList.remove('active-step');
                loginStepOne.classList.add('active-step');
            }
        } catch (error) {
            console.error('Error completing login:', error);
            showMessage('An error occurred during login. Please try again.', true);
            
            // Go back to first step
            loginStepCaptcha.classList.remove('active-step');
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
    
    // Update navbar UI on page load
    updateNavbarUI();
});

// Helper function to show messages
function showMessage(message, isError) {
    const messageElement = document.createElement('div');
    messageElement.classList.add(isError ? 'error-popup' : 'success-popup');
    messageElement.textContent = message;
    document.body.appendChild(messageElement);
    setTimeout(() => messageElement.remove(), 3000);
}

// Helper function to close modals
function closeModal(modal) {
    if (modal) modal.style.display = 'none';
}
