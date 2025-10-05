document.addEventListener('DOMContentLoaded', function() {
    // Admin signup modal elements
    const adminSignupModal = document.getElementById('adminSignupModal');
    const adminSignupModalClose = document.getElementById('adminSignupModalClose');
    const adminSignupForm = document.getElementById('admin-signup-form');
    const adminLoginModal = document.getElementById('adminLoginModal');
    const switchToAdminLoginLink = document.getElementById('switchToAdminLoginLink');
    const sendAdminCodeBtn = document.getElementById('sendAdminCodeBtn');
    const adminVerificationSection = document.getElementById('admin-verification-section');
    const adminVerificationCode = document.getElementById('admin-verification-code');
    const adminCodeMessage = document.getElementById('adminCodeMessage');

    // Password validation elements
    const adminPassword = document.getElementById('admin-password');
    const adminConfirmPassword = document.getElementById('admin-confirm-password');
    const adminPasswordMessage = document.getElementById('admin-passwordMessage');
    const adminConfirmPasswordMessage = document.getElementById('admin-confirmPasswordMessage');

    // Close admin signup modal
    if (adminSignupModalClose && adminSignupModal) {
        adminSignupModalClose.addEventListener('click', function() {
            adminSignupModal.style.display = 'none';
            document.body.style.overflow = '';
            resetAdminSignupForm();
        });
    }

    // Switch to admin login
    if (switchToAdminLoginLink && adminSignupModal && adminLoginModal) {
        switchToAdminLoginLink.addEventListener('click', function() {
            adminSignupModal.style.display = 'none';
            adminLoginModal.style.display = 'block';
        });
    }

    // Reset admin signup form
    function resetAdminSignupForm() {
        if (adminSignupForm) adminSignupForm.reset();
        if (adminVerificationSection) adminVerificationSection.style.display = 'none';
        if (adminCodeMessage) adminCodeMessage.style.display = 'none';
        if (adminPasswordMessage) adminPasswordMessage.textContent = '';
        if (adminConfirmPasswordMessage) adminConfirmPasswordMessage.textContent = '';
        sessionStorage.removeItem('adminSignupOtpEmail');
    }

    // Send verification code
    if (sendAdminCodeBtn) {
        sendAdminCodeBtn.addEventListener('click', async function() {
            const email = document.getElementById('admin-email').value;

            if (!email || !validateEmail(email)) {
                showMessage('Please enter a valid email address.', true);
                return;
            }

            sendAdminCodeBtn.disabled = true;
            const originalText = sendAdminCodeBtn.textContent;
            sendAdminCodeBtn.textContent = 'Sending...';

            try {
                const response = await fetch('/api/admin/send-verification', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email }),
                    credentials: 'same-origin'
                });

                const data = await response.json();
                if (data.success) {
                    showMessage('Verification code sent! Check your email.', false);
                    adminVerificationSection.style.display = 'block';

                    // ✅ Store email used for OTP
                    sessionStorage.setItem('adminSignupOtpEmail', email);

                    // Disable resend button for 60 seconds
                    let timeLeft = 60;
                    const interval = setInterval(() => {
                        timeLeft--;
                        sendAdminCodeBtn.textContent = `Resend (${timeLeft}s)`;
                        if (timeLeft <= 0) {
                            clearInterval(interval);
                            sendAdminCodeBtn.disabled = false;
                            sendAdminCodeBtn.textContent = originalText;
                        }
                    }, 1000);
                } else {
                    showMessage(data.message || 'Failed to send verification code.', true);
                    sendAdminCodeBtn.disabled = false;
                    sendAdminCodeBtn.textContent = originalText;
                }
            } catch (error) {
                console.error('Error sending verification code:', error);
                showMessage('An error occurred. Please try again later.', true);
                sendAdminCodeBtn.disabled = false;
                sendAdminCodeBtn.textContent = originalText;
            }
        });
    }

    // ✅ Reset OTP if email changes
    const adminEmailInput = document.getElementById('admin-email');
    if (adminEmailInput) {
        adminEmailInput.addEventListener('input', () => {
            const currentEmail = adminEmailInput.value.trim();
            const storedEmail = sessionStorage.getItem('adminSignupOtpEmail');

            if (storedEmail && storedEmail !== currentEmail) {
                sessionStorage.removeItem('adminSignupOtpEmail');
                adminVerificationSection.style.display = 'none';
                adminVerificationCode.value = '';
                adminCodeMessage.textContent = '';
                showMessage('You changed your email. Please resend the verification code.', true);
            }
        });
    }

    // Password validation
    if (adminPassword) {
        adminPassword.addEventListener('input', function() {
            validatePassword(this.value, adminPasswordMessage);
        });
    }

    if (adminConfirmPassword && adminPassword) {
        adminConfirmPassword.addEventListener('input', function() {
            validateConfirmPassword(adminPassword.value, this.value, adminConfirmPasswordMessage);
        });
    }

    // Admin signup form submission
    if (adminSignupForm) {
        adminSignupForm.addEventListener('submit', async function(event) {
            event.preventDefault();

            // Get form values
            const firstName = document.getElementById('admin-firstName').value;
            const lastName = document.getElementById('admin-lastName').value;
            const username = document.getElementById('admin-username').value;
            const email = document.getElementById('admin-email').value;
            const phoneNumber = document.getElementById('admin-phoneNumber').value;
            const role = document.getElementById('admin-role').value;
            const password = document.getElementById('admin-password').value;
            const confirmPassword = document.getElementById('admin-confirm-password').value;
            const termsCheckbox = document.getElementById('admin-terms-checkbox');
            const termsError = document.getElementById('admin-terms-error');
            const verificationCode = document.getElementById('admin-verification-code').value;

            // Validate required fields
            if (!firstName || !lastName || !username || !email || !phoneNumber || !role || !password || !confirmPassword) {
                showMessage('Please fill in all required fields.', true);
                return;
            }
            if (!validateEmail(email)) {
                showMessage('Please enter a valid email address.', true);
                return;
            }
            if (!validatePassword(password, adminPasswordMessage)) return;
            if (password !== confirmPassword) {
                adminConfirmPasswordMessage.textContent = 'Passwords do not match.';
                adminConfirmPasswordMessage.style.color = 'red';
                return;
            }
            if (!termsCheckbox.checked) {
                termsError.style.display = 'block';
                return;
            } else {
                termsError.style.display = 'none';
            }

            // ✅ Check stored email matches before verifying OTP
            const storedEmail = sessionStorage.getItem('adminSignupOtpEmail');
            if (storedEmail && storedEmail !== email) {
                showMessage('Email does not match the one used for verification. Please resend the code.', true);
                return;
            }

            if (adminVerificationSection.style.display !== 'none' && !verificationCode) {
                adminCodeMessage.textContent = 'Please enter the verification code.';
                adminCodeMessage.style.display = 'block';
                return;
            }

            // Disable submit button
            const submitBtn = adminSignupForm.querySelector('button[type="submit"]');
            const originalText = submitBtn.textContent;
            submitBtn.disabled = true;
            submitBtn.textContent = 'Submitting...';

            try {
                let verified = true;
                if (adminVerificationSection.style.display !== 'none') {
                    const verifyResponse = await fetch('/api/admin/verify-code', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ email, code: verificationCode }),
                        credentials: 'same-origin'
                    });
                    const verifyData = await verifyResponse.json();
                    if (!verifyData.success) {
                        adminCodeMessage.textContent = verifyData.message || 'Invalid verification code.';
                        adminCodeMessage.style.display = 'block';
                        submitBtn.disabled = false;
                        submitBtn.textContent = originalText;
                        return;
                    }
                    verified = true;
                }

                // Submit signup request
                const response = await fetch('/api/admin/signup', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        firstName, lastName, username, email, password, phoneNumber, role, verified
                    }),
                    credentials: 'same-origin'
                });

                const data = await response.json();
                if (data.success) {
                    showMessage('Account request submitted successfully! You will be notified once approved.', false);
                    adminSignupModal.style.display = 'none';
                    resetAdminSignupForm();

                    const accountPendingModal = document.getElementById('accountPendingModal');
                    if (accountPendingModal) {
                        accountPendingModal.style.display = 'block';
                    }
                } else {
                    showMessage(data.message || 'Failed to submit account request.', true);
                }
            } catch (error) {
                console.error('Error submitting admin signup:', error);
                showMessage('An error occurred. Please try again later.', true);
            } finally {
                submitBtn.disabled = false;
                submitBtn.textContent = originalText;
            }
        });
    }

    // Validation helpers
    function validateEmail(email) {
        const re = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
        return re.test(String(email).toLowerCase());
    }
    function validatePassword(password, messageElement) {
        if (password.length < 8) {
            messageElement.textContent = 'Password must be at least 8 characters long.'; messageElement.style.color = 'red'; return false;
        } else if (!/[A-Z]/.test(password)) {
            messageElement.textContent = 'Password must contain at least one uppercase letter.'; messageElement.style.color = 'red'; return false;
        } else if (!/[a-z]/.test(password)) {
            messageElement.textContent = 'Password must contain at least one lowercase letter.'; messageElement.style.color = 'red'; return false;
        } else if (!/[0-9]/.test(password)) {
            messageElement.textContent = 'Password must contain at least one number.'; messageElement.style.color = 'red'; return false;
        } else {
            messageElement.textContent = 'Password is strong!'; messageElement.style.color = 'green'; return true;
        }
    }
    function validateConfirmPassword(password, confirmPassword, messageElement) {
        if (password === confirmPassword) {
            messageElement.textContent = 'Passwords match!'; messageElement.style.color = 'green'; return true;
        } else {
            messageElement.textContent = 'Passwords do not match.'; messageElement.style.color = 'red'; return false;
        }
    }

    // UI helpers
    function showMessage(message, isError) {
        const messageBox = document.createElement('div');
        messageBox.className = isError ? 'message error' : 'message success';
        messageBox.textContent = message;
        messageBox.style.position = 'fixed';
        messageBox.style.top = '20px';
        messageBox.style.left = '50%';
        messageBox.style.transform = 'translateX(-50%)';
        messageBox.style.padding = '10px 20px';
        messageBox.style.borderRadius = '5px';
        messageBox.style.backgroundColor = isError ? '#ffdddd' : '#ddffdd';
        messageBox.style.color = isError ? '#ff0000' : '#00aa00';
        messageBox.style.boxShadow = '0 2px 5px rgba(0,0,0,0.2)';
        messageBox.style.zIndex = '10000';
        document.body.appendChild(messageBox);
        setTimeout(() => {
            messageBox.style.opacity = '0';
            messageBox.style.transition = 'opacity 0.5s';
            setTimeout(() => { document.body.removeChild(messageBox); }, 500);
        }, 3000);
    }

    function togglePassword(inputId, button) {
        const input = document.getElementById(inputId);
        const type = input.getAttribute('type') === 'password' ? 'text' : 'password';
        input.setAttribute('type', type);
        const img = button.querySelector('img');
        img.src = (type === 'text') ? '/images/eye-slash.png' : '/images/eye.png';
        img.alt = (type === 'text') ? 'Hide Password' : 'Show Password';
    }

    window.togglePassword = togglePassword;
    window.showMessage = showMessage;
});
