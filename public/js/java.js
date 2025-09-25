
let authCheckInProgress = false;
let lastAuthState = null;

function checkAuthStatus() {
    if (authCheckInProgress) return;
    authCheckInProgress = true;
    
    const timestamp = new Date().getTime();
    
    fetch(`/check-auth?_=${timestamp}`, {
        method: 'GET',
        credentials: 'same-origin',
        headers: {
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache'
        }
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('Network response was not ok');
        }
        return response.json();
    })
    .then(data => {
        console.log('Auth check response:', data);
        
        const currentState = localStorage.getItem("isLoggedIn") === "true";
        
        if (lastAuthState === null || data.isLoggedIn !== lastAuthState) {
            lastAuthState = data.isLoggedIn;
            
            if (data.isLoggedIn !== currentState) {
                if (data.isLoggedIn) {
                    localStorage.setItem("isLoggedIn", "true");
                } else {
                    localStorage.removeItem("isLoggedIn");
                }
            }
            
            updateUI();
        }
    })
    .catch(error => {
        console.error('Auth check error:', error);
    })
    .finally(() => {
        authCheckInProgress = false;
    });
}

document.addEventListener("DOMContentLoaded", () => {

    checkAuthStatus();
    
    document.querySelectorAll(".modal").forEach((modal) => 
        (modal.style.display = "none"));
    
    const elements = { 
        loginModal: document.getElementById("loginModal"), 
        loginModalClose: document.querySelector("#loginModal .close"), 
        forgotPasswordModalClose: document.querySelector("#forgotPasswordModal .close"), 
        loginBtn: document.getElementById("loginBtn"), 
        loginBtnWrapper: document.getElementById("loginBtnWrapper"),
        userProfile: document.getElementById("userProfile"),
        profileDropdown: document.getElementById("profileDropdown"),
        profileIconWrapper: document.getElementById("profileIconWrapper"),
        loginForm: document.getElementById("loginForm"),
        logoutBtn: document.getElementById("logoutBtn"), 
        forgotPasswordModal: document.getElementById("forgotPasswordModal"),
        forgotPasswordForm: document.getElementById("forgotPasswordForm"),
        forgotEmail: document.getElementById("forgotEmail"),
        emailSection: document.getElementById("emailSection"), 
        otpSection: document.getElementById("otpSection"),
        otpCode: document.getElementById("otpCode"),
        resetPasswordSection: document.getElementById("resetPasswordSection"), 
        successSection: document.getElementById("successSection"), 
        newPassword: document.getElementById("newPassword"), 
        confirmPassword: document.getElementById("confirmPassword"), 
        passwordMessage: document.getElementById("passwordMessage"),
        confirmPasswordMessage: document.getElementById("confirmPasswordMessage"),
        switchToAdminBtn: document.getElementById("switchToAdminBtn"), 
        notificationIcon: document.getElementById("notificationIcon"),
        notificationDropdown: document.getElementById("notificationDropdown"), 
        bookingStatus: document.getElementById("bookingStatus"),
        signupModal: document.getElementById("signupModal"), 
        signupModalClose: document.getElementById("signupModalClose"), 
        signupForm: document.getElementById("signup-form"), 
        verificationPopup: document.getElementById("verification-popup"),
        signupSuccessPopup: document.getElementById("signup-success-popup"),
        adminLoginModal: document.getElementById("adminLoginModal"), 
        adminLoginModalClose: document.getElementById("adminLoginModalClose"),
        adminForgotPasswordModal: document.getElementById("adminForgotPasswordModal"), 
        adminForgotPasswordModalClose: document.getElementById("adminForgotPasswordModalClose"),
        adminSignupSuccessModal: document.getElementById("adminSignupSuccessModal"), 
        adminSignupSuccessModalClose: document.getElementById("adminSignupSuccessModalClose"),
        adminSignupSuccessBtn: document.getElementById("adminSignupSuccessBtn"), 
        adminLoginForm: document.getElementById("adminLoginForm"), 
        adminSignupForm: document.getElementById("adminSignupForm"),
        adminForgotPasswordLink: document.getElementById("adminForgotPasswordLink"),
        adminVerificationModal: document.getElementById("adminVerificationModal"),
        adminVerificationModalClose: document.getElementById("adminVerificationModalClose"),
        verifyAdminCodeBtn: document.getElementById("verifyAdminCodeBtn"),
        resendAdminCodeBtn: document.getElementById("resendAdminCodeBtn"),
        adminVerificationCode: document.getElementById("adminVerificationCode"),
        accountPendingModal: document.getElementById("accountPendingModal"),
        accountPendingModalClose: document.getElementById("accountPendingModalClose"),
        accountPendingBtn: document.getElementById("accountPendingBtn"),
    }; 
    function updateUI() { 
        const isLoggedIn = localStorage.getItem("isLoggedIn") === "true"; 
        if (elements.loginBtnWrapper) 
            elements.loginBtnWrapper.style.display = isLoggedIn ? "none" : "block"; 
        if (elements.userProfile) 
            elements.userProfile.style.display = isLoggedIn ? "block" : "none";
        
        // Add this code to show/hide notification bell
        const notificationWrapper = document.getElementById("notificationWrapper");
        if (notificationWrapper) {
            notificationWrapper.style.display = isLoggedIn ? "block" : "none";
        }
        
        // Add this line to update the navbar UI
        if (window.updateNavbarUI) {
            window.updateNavbarUI();
        }
            
        // Only fetch booking status if logged in and the element exists
        if (isLoggedIn && elements.bookingStatus) {
            fetchBookingStatus();
        }
    }
    
    // Modal utility functions
    function openModal(modal) { 
        if (modal) modal.style.display = "flex"; 
    } 
    
    function closeModal(modal) { 
        if (modal) modal.style.display = "none"; 
    } 
    
    function closeAllModals() { 
        document.querySelectorAll(".modal").forEach(closeModal); 
    } 
    
    // Show error/success message 
    function showMessage(message, isError = false) { 
        const messageElement = document.createElement("div"); 
        messageElement.classList.add(isError ? "error-popup" : "success-popup");
        messageElement.textContent = message; 
        document.body.appendChild(messageElement);
        setTimeout(() => messageElement.remove(), 3000); 
    } 
    elements.notificationIcon?.addEventListener("click", (event) => { 
        event.stopPropagation();
        if (elements.notificationDropdown) { 
            const isVisible = elements.notificationDropdown.style.display === "block";
            elements.notificationDropdown.style.display = isVisible ? "none" : "block"; 
        }
    });
    
    // Handle Profile Dropdown Toggle 
    elements.profileIconWrapper?.addEventListener("click", (event) => { 
        event.stopPropagation(); 
        if (elements.profileDropdown) { 
            elements.profileDropdown.style.display = 
                elements.profileDropdown.style.display === "block" ? "none" : "block"; 
        } 
    }); 
    window.addEventListener("click", (event) => { 
        if (elements.notificationDropdown && 
            elements.notificationIcon && 
            !elements.notificationIcon.contains(event.target) && 
            !elements.notificationDropdown.contains(event.target)) { 
            elements.notificationDropdown.style.display = "none"; 
        } 
        
       if (elements.profileDropdown && 
            elements.profileIconWrapper && 
            !elements.profileIconWrapper.contains(event.target) && 
            !elements.profileDropdown.contains(event.target)) { 
            elements.profileDropdown.style.display = "none"; 
        } 
    });
    // Open login modal 
    elements.loginBtn?.addEventListener("click", () => openModal(elements.loginModal)); 
    
    // Close login modal 
    elements.loginModalClose?.addEventListener("click", () => closeModal(elements.loginModal)); 
    
    // Close forgot password modal 
    elements.forgotPasswordModalClose?.addEventListener("click", () => closeModal(elements.forgotPasswordModal)); 
    // Logout handler
elements.logoutBtn?.addEventListener("click", async (e) => { 
    e.preventDefault(); 
    try { 
        const response = await fetch("/logout", { 
            method: "GET",
            credentials: 'same-origin'
        }); 
        
        if (response.ok) {
            // Clear all auth-related storage
            localStorage.removeItem("isLoggedIn"); 
            sessionStorage.removeItem("isLoggedIn");
            lastAuthState = false; // Update our tracking variable
            
            // Update UI immediately
            if (elements.loginBtnWrapper) 
                elements.loginBtnWrapper.style.display = "block"; 
            if (elements.userProfile) 
                elements.userProfile.style.display = "none";
                
            // Hide notification bell
            const notificationWrapper = document.getElementById("notificationWrapper");
            if (notificationWrapper) {
                notificationWrapper.style.display = "none";
            }
            
            // Show success message
            showMessage("You have been logged out successfully");
            
            // Optional: Redirect to home page
            window.location.href = '/';
        } else {
            throw new Error("Logout request failed");
        }
    } catch (error) { 
        console.error("Logout error:", error); 
        showMessage("Logout failed. Try again.", true); 
    } 
});


    // Open forgot password modal 
    document.querySelectorAll('p a[href="javascript:void(0);"]').forEach((link) => { 
        if (link.id !== "switchToLoginLink" && link.id !== "adminForgotPasswordLink") { 
            link.addEventListener("click", () => { 
                closeAllModals(); 
                openForgotPasswordModal(); 
            }); 
        } 
    }); 
    
    // Set up event listener for forgot password link in the login modal 
    const forgotPasswordLink = document.getElementById("forgotPasswordLink"); 
    if (forgotPasswordLink) { 
        forgotPasswordLink.addEventListener('click', function(e) { 
            e.preventDefault(); 
            closeModal(elements.loginModal); 
            openForgotPasswordModal(); 
        }); 
    } 
    
        // Check for notifications
        function checkNotifications() {
            fetch('/api/user-notifications')
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        const bookingStatus = document.getElementById('bookingStatus');
                        if (bookingStatus) {
                            if (data.notifications && data.notifications.length > 0) {
                                bookingStatus.textContent = `You have ${data.notifications.length} active booking(s).`;
                                
                                // Add notification badge if there are new notifications
                                if (data.newNotifications > 0) {
                                    const notificationIcon = document.getElementById('notificationIcon');
                                    if (notificationIcon) {
                                        const badge = document.createElement('span');
                                        badge.className = 'notification-badge';
                                        badge.textContent = data.newNotifications;
                                        notificationIcon.appendChild(badge);
                                    }
                                }
                            } else {
                                bookingStatus.textContent = 'You have no bookings at the moment.';
                            }
                        }
                    }
                })
                .catch(error => {
                    console.error('Error checking notifications:', error);
                });
        }

        checkNotifications();
    // Add event listeners for back links in password reset steps 
    document.querySelectorAll('.back-link a').forEach(link => { 
        link.addEventListener('click', function(e) { 
            e.preventDefault(); 
            const targetStep = this.getAttribute('onclick').match(/'([^']+)'/)[1]; 
            if (targetStep.startsWith('admin')) { 
                showAdminResetStep(targetStep); 
            } else { 
                showResetStep(targetStep); 
            } 
        }); 
    }); 
    
    // SIGNUP MODAL FUNCTIONALITY 
    // Update the login form to include signup link 
    const signupLink = document.querySelector('#loginForm + p a[href="/signup"]'); 
    if (signupLink) { 
        signupLink.href = 'javascript:void(0);'; 
        signupLink.addEventListener('click', function(e) { 
            e.preventDefault(); 
            closeModal(elements.loginModal); 
            openModal(elements.signupModal); 
        }); 
    } 
    
    // Switch from signup to login 
    const switchToLoginLink = document.getElementById('switchToLoginLink'); 
    if (switchToLoginLink) { 
        switchToLoginLink.addEventListener('click', function() { 
            closeModal(elements.signupModal); 
            openModal(elements.loginModal); 
        }); 
    } 
    
    // Close signup modal when clicking the X 
    if (elements.signupModalClose) { 
        elements.signupModalClose.addEventListener('click', function() { 
            closeModal(elements.signupModal); 
        }); 
    } 
    
    // Close verification popup when clicking the button 
    const verificationPopupBtn = document.getElementById('verification-popup-btn'); 
    if (verificationPopupBtn) { 
        verificationPopupBtn.addEventListener('click', function() { 
            closeModal(elements.verificationPopup); 
        }); 
    } 
    
    // Close modals when clicking outside 
    window.addEventListener('click', function(event) { 
        if (event.target === elements.signupModal) { 
            closeModal(elements.signupModal); 
        } 
        if (event.target === elements.verificationPopup) { 
            closeModal(elements.verificationPopup); 
        } 
        if (event.target === elements.signupSuccessPopup) { 
            closeModal(elements.signupSuccessPopup); 
        } 
        if (event.target === elements.adminLoginModal) { 
            closeModal(elements.adminLoginModal); 
        } 
        if (event.target === elements.adminForgotPasswordModal) { 
            closeModal(elements.adminForgotPasswordModal); 
        } 
        if (event.target === elements.adminSignupSuccessModal) { 
            closeModal(elements.adminSignupSuccessModal); 
        } 
        // Admin verification modals
        if (event.target === elements.adminVerificationModal) {
            closeModal(elements.adminVerificationModal);
            clearInterval(adminVerificationTimer);
        }
        if (event.target === elements.accountPendingModal) {
            closeModal(elements.accountPendingModal);
        }
        
    }); 
    if (elements.adminVerificationModalClose) {
        elements.adminVerificationModalClose.addEventListener('click', function() {
            closeModal(elements.adminVerificationModal);
            clearInterval(adminVerificationTimer);
        });
    }
    if (elements.accountPendingModalClose) {
        elements.accountPendingModalClose.addEventListener('click', function() {
            closeModal(elements.accountPendingModal);
            openModal(elements.adminLoginModal);
        });
    }
    if (elements.accountPendingBtn) {
        elements.accountPendingBtn.addEventListener('click', function() {
            closeModal(elements.accountPendingModal);
            openModal(elements.LoginModal);
        });
    }
    
    // Signup password validation for signup (using jQuery
    const signupPassword = document.getElementById('signup-password'); 
    if (signupPassword) { 
        signupPassword.addEventListener('input', function() { 
            const password = this.value; 
            const message = document.getElementById('signup-passwordMessage'); 
            const validation = validatePassword(password); 
            message.style.color = validation.isValid ? 'green' : 'red'; 
            message.textContent = validation.message; 
        }); 
    } 
    
    // Confirm password validation for signup 
    const signupConfirmPassword = document.getElementById('signup-confirm-password'); 
    if (signupConfirmPassword) { 
        signupConfirmPassword.addEventListener('input', function() { 
            const password = document.getElementById('signup-password').value; 
            const confirmPassword = this.value; 
            const message = document.getElementById('signup-confirmPasswordMessage'); 
            if (password === confirmPassword && password.length > 0) { 
                message.style.color = 'green'; 
                message.textContent = '✔ Passwords match!'; 
            } else { 
                message.style.color = 'red'; 
                message.textContent = '❌ Passwords do not match.'; 
            } 
        }); 
    } 
    
    // Send verification code - IMPROVED VERSION 
    const sendCodeBtn = document.getElementById('sendCodeBtn'); 
    if (sendCodeBtn) { 
        sendCodeBtn.addEventListener('click', function() { 
            const email = document.getElementById('signup-email').value.trim(); 
            if (!email) { 
                showMessage("Please enter your email first!", true); 
                return; 
            } 
            
            // Show loading state 
            const originalText = this.textContent; 
            this.disabled = true; 
            this.textContent = "Sending..."; 
            
            fetch('/send-code', { 
                method: 'POST', 
                headers: { 'Content-Type': 'application/json' }, 
                body: JSON.stringify({ email }) 
            }) 
            .then(response => { 
                // First check if the response is ok 
                if (!response.ok) { 
                    throw new Error(`Server responded with status: ${response.status}`); 
                } 
                return response.text().then(text => { 
                    try { 
                        return JSON.parse(text); 
                    } catch (e) { 
                        console.error('JSON parse error:', e); 
                        console.log('Raw response:', text); 
                        throw new Error('Invalid JSON response from server'); 
                    } 
                }); 
            }) 
            .then(data => { 
                if (data.success) { 
                    showMessage("Verification code sent successfully!", false); 
                    openModal(elements.verificationPopup); 
                    document.getElementById('verification-section').style.display = 'block'; 
                } else { 
                    showMessage(`Error: ${data.message || 'Could not send verification code'}`, true); 
                } 
            }) 
            .catch(error => { 
                console.error('Error sending verification code:', error); 
                showMessage(`Failed to send verification code: ${error.message}`, true); 
            }) 
            .finally(() => { 
                // Restore button state 
                this.disabled = false; 
                this.textContent = originalText; 
            }); 
        }); 
    } 
    // Find the signup form submission handler in java.js and update it
if (elements.signupForm) {
    elements.signupForm.addEventListener('submit', function(e) {
        e.preventDefault();
        const username = document.getElementById('signup-username').value.trim();
        const email = document.getElementById('signup-email').value.trim();
        const phoneNumber = document.getElementById('signup-phonenumber').value.trim();
        const password = document.getElementById('signup-password').value;
        const confirmPassword = document.getElementById('signup-confirm-password').value;
        const verificationCode = document.getElementById('verification-code')?.value.trim();
        
        // Form validation
        if (!username || !email || !phoneNumber || !password || !confirmPassword) {
            showMessage("Please fill in all required fields.", true);
            return;
        }
        
        // Check password validity
        const passwordValidation = validatePassword(password);
        if (!passwordValidation.isValid) {
            showMessage(passwordValidation.message, true);
            return;
        }
        
        if (password !== confirmPassword) {
            showMessage('Passwords do not match.', true);
            return;
        }
        
        // Check if verification section is visible but code wasn't entered
        const verificationSection = document.getElementById('verification-section');
        const verificationSectionVisible = verificationSection && verificationSection.style.display !== 'none';
        const codeMessage = document.getElementById('codeMessage');
        
        if (verificationSectionVisible && !verificationCode) {
            if (codeMessage) {
                codeMessage.textContent = 'Please enter the verification code sent to your email.';
                codeMessage.style.display = 'block';
            } else {
                showMessage('Please enter the verification code sent to your email.', true);
            }
            return;
        }
        
        // Show loading state
        const submitBtn = this.querySelector('button[type="submit"]');
        const originalBtnText = submitBtn.textContent;
        submitBtn.disabled = true;
        submitBtn.textContent = "Creating Account...";
        
        const userData = {
            username,
            email,
            phoneNumber,
            password,
            verificationCode: verificationCode || null
        };
        
        fetch('/signup', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(userData)
        })
        .then(response => {
            if (!response.ok) {
                return response.json().then(data => {
                    throw new Error(data.message || `Server error: ${response.status}`);
                });
            }
            return response.json();
        })
        .then(data => {
            if (data.success) {
                closeModal(elements.signupModal);
                
                // Handle auto-login
                if (data.autoLogin) {
                    // Set login state in localStorage and sessionStorage
                    localStorage.setItem("isLoggedIn", "true");
                    sessionStorage.setItem("isLoggedIn", "true");
                    lastAuthState = true;
                    
                    // Update UI for logged-in user
                    updateUI();
                    
                    // Show success message
                    showMessage("Account created successfully! You are now logged in.", false);
                    
                    // Redirect to home page or dashboard
                    setTimeout(() => {
                        window.location.href = '/';
                    }, 1500);
                } else {
                    // Show the original success popup if auto-login is not enabled
                    openModal(elements.signupSuccessPopup);
                    
                    let countdown = 5;
                    const countdownElement = document.getElementById('countdown');
                    const interval = setInterval(() => {
                        if (countdownElement) countdownElement.textContent = countdown;
                        countdown--;
                        if (countdown < 0) {
                            clearInterval(interval);
                            window.location.href = '/';
                        }
                    }, 1000);
                    
                    const redirectBtn = document.getElementById('redirectBtn');
                    if (redirectBtn) {
                        redirectBtn.addEventListener('click', function() {
                            window.location.href = '/';
                        }, { once: true });
                    }
                }
            } else {
                showMessage('Error creating user: ' + (data.message || 'Unknown error'), true);
            }
        })
        .catch(error => {
            console.error('Signup error:', error);
            showMessage(error.message || "Something went wrong. Please try again later.", true);
        })
        .finally(() => {
            // Restore button state
            submitBtn.disabled = false;
            submitBtn.textContent = originalBtnText;
        });
    });
}

    
    // ADMIN LOGIN MODAL FUNCTIONALITY 
    // Open admin login modal from user login modal 
    if (elements.switchToAdminBtn) { 
        elements.switchToAdminBtn.addEventListener('click', function() { 
            console.log("Switch to Admin button clicked"); 
            closeModal(elements.loginModal); 
            console.log("Opening admin login modal"); 
            openModal(elements.adminLoginModal); 
        }); 
    } 
    
    // Close admin login modal 
    if (elements.adminLoginModalClose) { 
        elements.adminLoginModalClose.addEventListener('click', function() { 
            closeModal(elements.adminLoginModal); 
        }); 
    } 
    
    // Tab functionality for admin login/signup 
    const tabBtns = document.querySelectorAll('.tab-btn'); 
    tabBtns.forEach(btn => { 
        btn.addEventListener('click', function() { 
            const tabName = this.getAttribute('data-tab'); 
            // Remove active class from all tabs 
            tabBtns.forEach(btn => btn.classList.remove('active')); 
            document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active')); 
            
            // Add active class to current tab 
            this.classList.add('active'); 
            document.getElementById(`${tabName}-tab`).classList.add('active'); 
        }); 
    }); 
    
    // Admin forgot password link 
    if (elements.adminForgotPasswordLink) { 
        elements.adminForgotPasswordLink.addEventListener('click', function() { 
            closeModal(elements.adminLoginModal); 
            openModal(elements.adminForgotPasswordModal); 
        }); 
    } 
    
    // Close admin forgot password modal 
    if (elements.adminForgotPasswordModalClose) { 
        elements.adminForgotPasswordModalClose.addEventListener('click', function() { 
            closeModal(elements.adminForgotPasswordModal); 
            openModal(elements.adminLoginModal); 
            resetAdminPasswordForm(); 
        }); 
    } 
    
    // Close admin signup success modal 
    if (elements.adminSignupSuccessModalClose) { 
        elements.adminSignupSuccessModalClose.addEventListener('click', function() { 
            closeModal(elements.adminSignupSuccessModal); 
        }); 
    } 
    
    // Return to login from signup success 
    if (elements.adminSignupSuccessBtn) { 
        elements.adminSignupSuccessBtn.addEventListener('click', function() { 
            closeModal(elements.adminSignupSuccessModal); 
            openModal(elements.adminLoginModal); 
            // Switch to login tab 
            tabBtns.forEach(btn => btn.classList.remove('active')); 
            document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active')); 
            document.querySelector('[data-tab="login"]').classList.add('active'); 
            document.getElementById('login-tab').classList.add('active'); 
        }); 
    } 
    
    // Admin signup form submission 
    if (elements.adminSignupForm) { 
        elements.adminSignupForm.addEventListener('submit', function(e) { 
            e.preventDefault(); 
            const fullname = document.getElementById('admin-signup-fullname').value.trim(); 
            const username = document.getElementById('admin-signup-username').value.trim(); 
            const email = document.getElementById('admin-signup-email').value.trim(); 
            const phone = document.getElementById('admin-signup-phone').value.trim(); 
            const role = document.getElementById('admin-signup-role').value; 
            const password = document.getElementById('admin-signup-password').value; 
            const confirmPassword = document.getElementById('admin-signup-confirm').value; 
            
            // Form validation 
            if (!fullname || !username || !email || !phone || !role || !password || !confirmPassword) { 
                showMessage("Please fill in all required fields.", true); 
                return; 
            } 
            
            // Check password validity 
            const passwordValidation = validatePassword(password); 
            if (!passwordValidation.isValid) { 
                showMessage(passwordValidation.message, true); 
                return; 
            } 
            
            if (password !== confirmPassword) { 
                showMessage('Passwords do not match.', true); 
                return; 
            } 
            
            // Show loading state 
            const submitBtn = this.querySelector('button[type="submit"]'); 
            const originalBtnText = submitBtn.textContent; 
            submitBtn.disabled = true; 
            submitBtn.textContent = "Submitting..."; 
            
            const userData = { 
                fullname, 
                username, 
                email, 
                phone, 
                role, 
                password 
            }; 
            
            fetch('/admin-signup', { 
                method: 'POST', 
                headers: { 'Content-Type': 'application/json' }, 
                body: JSON.stringify(userData) 
            }) 
            .then(response => { 
                if (!response.ok) { 
                    return response.json().then(data => { 
                        throw new Error(data.message || `Server error: ${response.status}`); 
                    }); 
                } 
                return response.json(); 
            }) 
            .then(data => { 
                if (data.success) { 
                    closeModal(elements.adminLoginModal); 
                    openModal(elements.adminSignupSuccessModal); 
                    this.reset(); 
                } else { 
                    showMessage(`Signup failed: ${data.message || 'Unknown error'}`, true); 
                } 
            }) 
            .catch(error => { 
                console.error('Admin signup error:', error); 
                showMessage(error.message || "Signup failed. Please try again.", true); 
            }) 
            .finally(() => { 
                // Restore button state 
                submitBtn.disabled = false; 
                submitBtn.textContent = originalBtnText; 
            }); 
        }); 
    } 
    
    // Password strength meter for admin signup and reset 
    const passwordInputs = document.querySelectorAll('#admin-signup-password, #adminNewPassword'); 
    passwordInputs.forEach(input => { 
        if (input) { 
            input.addEventListener('input', function() { 
                const password = this.value; 
                const strengthBar = this.parentElement.nextElementSibling.querySelector('.strength-bar'); 
                const strengthText = this.parentElement.nextElementSibling.querySelector('.strength-text'); 
                
                if (!strengthBar || !strengthText) return; 
                
                // Calculate password strength 
                const validation = validatePassword(password); 
                let strength = 0; 
                if (password.length >= 8) strength += 20; 
                if (/[a-z]/.test(password)) strength += 20; 
                if (/[A-Z]/.test(password)) strength += 20; 
                if (/[0-9]/.test(password)) strength += 20; 
                if (/[^a-zA-Z0-9]/.test(password)) strength += 20; 
                
                // Update strength bar 
                strengthBar.style.width = strength + '%'; 
                
                // Update color based on strength 
                if (strength < 40) { 
                    strengthBar.style.backgroundColor = '#ff4d4d'; 
                    strengthText.textContent = 'Weak password'; 
                } else if (strength < 80) { 
                    strengthBar.style.backgroundColor = '#ffd633'; 
                    strengthText.textContent = 'Medium password'; 
                } else { 
                    strengthBar.style.backgroundColor = '#4CAF50'; 
                    strengthText.textContent = 'Strong password'; 
                } 
            }); 
        } 
    }); 
    
    // Password confirmation validation for admin 
    const confirmInputs = document.querySelectorAll('#admin-signup-confirm, #adminConfirmPassword'); 
    confirmInputs.forEach(input => { 
        if (input) { 
            input.addEventListener('input', function() { 
                const passwordId = this.id === 'admin-signup-confirm' ? 'admin-signup-password' : 'adminNewPassword';
                const password = document.getElementById(passwordId).value;
                const confirmPassword = this.value;
                const messageId = this.id === 'admin-signup-confirm' ? 'admin-signup-confirmMessage' : 'adminConfirmPasswordMessage';
                let messageElement = document.getElementById(messageId);
                
                if (!messageElement) {
                    messageElement = document.createElement('div');
                    messageElement.id = messageId;
                    messageElement.className = 'validation-message';
                    this.parentElement.appendChild(messageElement);
                }
                
                if (confirmPassword === '') {
                    messageElement.textContent = '';
                } else if (password === confirmPassword) {
                    messageElement.textContent = '✔ Passwords match!';
                    messageElement.style.color = '#4CAF50';
                } else {
                    messageElement.textContent = '❌ Passwords do not match.';
                    messageElement.style.color = '#ff4d4d';
                }
            });
        }
    });
});

// Define global functions for modal operations
function openLoginModal() {
    const modal = document.getElementById("loginModal");
    if (modal) modal.style.display = "flex";
}

function closeLoginModal() {
    const modal = document.getElementById("loginModal");
    if (modal) modal.style.display = "none";
}

function openSignupModal() {
    const modal = document.getElementById("signupModal");
    if (modal) modal.style.display = "flex";
    const loginModal = document.getElementById("loginModal");
    if (loginModal) loginModal.style.display = "none";
}

function closeSignupModal() {
    const modal = document.getElementById("signupModal");
    if (modal) modal.style.display = "none";
}

function openAdminLoginModal() {
    const modal = document.getElementById("adminLoginModal");
    if (modal) modal.style.display = "flex";
    const loginModal = document.getElementById("loginModal");
    if (loginModal) loginModal.style.display = "none";
}

function closeAdminLoginModal() {
    const modal = document.getElementById("adminLoginModal");
    if (modal) modal.style.display = "none";
}

// Password validation function
function validatePassword(password) {
    const minLength = /.{8,}/;
    const hasUpper = /[A-Z]/;
    const hasLower = /[a-z]/;
    const hasNumber = /[0-9]/;
    const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/;
    
    let missingCriteria = [];
    if (!minLength.test(password)) missingCriteria.push("8+ characters");
    if (!hasUpper.test(password)) missingCriteria.push("1 uppercase letter");
    if (!hasLower.test(password)) missingCriteria.push("1 lowercase letter");
    if (!hasNumber.test(password)) missingCriteria.push("1 number");
    if (!hasSpecial.test(password)) missingCriteria.push("1 special character");
    
    return {
        isValid: missingCriteria.length === 0,
        message: missingCriteria.length ? `❌ Missing: ${missingCriteria.join(', ')}` : "✔ Strong password!"
    };
}

// Toggle password visibility function
function togglePassword(fieldId, toggleBtn) {
    const passwordField = document.getElementById(fieldId);
    const img = toggleBtn.querySelector("img");
    
    if (passwordField.type === "password") {
        passwordField.type = "text";
        img.src = "/images/hidden.png";
        img.alt = "Hide Password";
    } else {
        passwordField.type = "password";
        img.src = "/images/eye.png";
        img.alt = "Show Password";
    }
}

// Show specific step in password reset process
function showResetStep(stepId) {
    // Hide all steps
    document.querySelectorAll('.password-reset-step').forEach(step => {
        step.classList.remove('active-step');
    });
    
    // Show the requested step
    const step = document.getElementById(stepId);
    if (step) {
        step.classList.add('active-step');
        
        // If showing password reset section, set up validation
        if (stepId === 'resetPasswordSection') {
            setupPasswordValidation();
        }
    }
}

// Set up password validation listeners
function setupPasswordValidation() {
    const newPassword = document.getElementById("newPassword");
    const confirmPassword = document.getElementById("confirmPassword");
    const passwordMessage = document.getElementById("passwordMessage");
    const confirmPasswordMessage = document.getElementById("confirmPasswordMessage");
    
    // Create message elements if they don't exist
    if (!passwordMessage && newPassword) {
        const msgElement = document.createElement("div");
        msgElement.id = "passwordMessage";
        msgElement.className = "validation-message";
        newPassword.insertAdjacentElement('afterend', msgElement);
    }
    
    if (!confirmPasswordMessage && confirmPassword) {
        const msgElement = document.createElement("div");
        msgElement.id = "confirmPasswordMessage";
        msgElement.className = "validation-message";
        confirmPassword.insertAdjacentElement('afterend', msgElement);
    }
    
    // Re-get the elements in case they were just created
    const pwdMsg = document.getElementById("passwordMessage");
    const confPwdMsg = document.getElementById("confirmPasswordMessage");
    
    if (newPassword && pwdMsg) {
        // Remove existing listeners to prevent duplicates
        newPassword.removeEventListener('input', passwordValidationHandler);
        // Add new listener
        newPassword.addEventListener('input', passwordValidationHandler);
    }
    
    if (newPassword && confirmPassword && confPwdMsg) {
        // Remove existing listeners to prevent duplicates
        confirmPassword.removeEventListener('input', confirmPasswordValidationHandler);
        // Add new listener
        confirmPassword.addEventListener('input', confirmPasswordValidationHandler);
    }
}

// Password validation handler
function passwordValidationHandler() {
    const password = this.value;
    const validation = validatePassword(password);
    const passwordMessage = document.getElementById("passwordMessage");
    
    if (passwordMessage) {
        passwordMessage.style.color = validation.isValid ? 'green' : 'red';
        passwordMessage.textContent = validation.message;
    }
    
    // Also update confirm password validation if it has content
    const confirmPassword = document.getElementById("confirmPassword");
    if (confirmPassword && confirmPassword.value) {
        const event = new Event('input');
        confirmPassword.dispatchEvent(event);
    }
}

// Confirm password validation handler
function confirmPasswordValidationHandler() {
    const newPassword = document.getElementById("newPassword");
    const confirmPasswordMessage = document.getElementById("confirmPasswordMessage");
    
    if (newPassword && confirmPasswordMessage) {
        const password = newPassword.value;
        const confirmPwd = this.value;
        
        if (password === confirmPwd && password.length > 0) {
            confirmPasswordMessage.style.color = 'green';
            confirmPasswordMessage.textContent = '✔ Passwords match!';
        } else {
            confirmPasswordMessage.style.color = 'red';
            confirmPasswordMessage.textContent = '❌ Passwords do not match.';
        }
    }
}

// Forgot Password Functions
function openForgotPasswordModal() {
    const modal = document.getElementById("forgotPasswordModal");
    if (modal) {
        // Reset all forms
        if (document.getElementById("forgotPasswordForm")) {
            document.getElementById("forgotPasswordForm").reset();
        }
        
        // Clear validation messages
        const passwordMessage = document.getElementById("passwordMessage");
        const confirmPasswordMessage = document.getElementById("confirmPasswordMessage");
        if (passwordMessage) passwordMessage.textContent = "";
        if (confirmPasswordMessage) confirmPasswordMessage.textContent = "";
        
        // Remove any existing status messages
        const statusMessages = modal.querySelectorAll(".status-message");
        statusMessages.forEach(msg => msg.remove());
        
        // Show only the first step
        showResetStep('emailSection');
        
        // Display the modal with flex to ensure centering
        modal.style.display = "flex";
        
        // Close the login modal if it's open
        const loginModal = document.getElementById("loginModal");
        if (loginModal) {
            loginModal.style.display = "none";
        }
    }
}

function closeForgotPasswordModal() {
    const modal = document.getElementById("forgotPasswordModal");
    if (modal) {
        modal.style.display = "none";
    }
}

function showStatusMessage(parentElement, message, isError = false) {
    // Remove any existing status messages
    const existingMessages = parentElement.querySelectorAll(".status-message");
    existingMessages.forEach(msg => msg.remove());
    
    // Create new status message
    const messageElement = document.createElement("div");
    messageElement.classList.add("status-message");
    messageElement.classList.add(isError ? "error-message" : "success-message");
    messageElement.textContent = message;
    
    // Insert after the button
    const button = parentElement.querySelector("button");
    if (button && button.parentNode) {
        button.parentNode.insertBefore(messageElement, button.nextSibling);
    } else {
        parentElement.appendChild(messageElement);
    }
}

function sendOTP() {
    const email = document.getElementById("forgotEmail").value;
    const emailSection = document.getElementById("emailSection");
    
    if (!email) {
        showStatusMessage(emailSection, "Please enter your email address.", true);
        return;
    }
    
    // Disable the button and show loading state
    const button = emailSection.querySelector("button");
    const originalText = button.textContent;
    button.disabled = true;
    button.textContent = "Sending...";
    
    fetch("/send-otp", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
    })
    .then(response => {
        if (!response.ok) {
            throw new Error(`Server responded with status: ${response.status}`);
        }
        return response.json();
    })
    .then(data => {
        if (data.success) {
            // Store email for later use
            sessionStorage.setItem("resetEmail", email);
            
            // Show success message briefly
            showStatusMessage(emailSection, data.message);
            
            // Move to OTP verification step after a short delay
            setTimeout(() => {
                showResetStep('otpSection');
            }, 1000);
        } else {
            showStatusMessage(emailSection, data.message || "Error sending OTP.", true);
        }
    })
    .catch(error => {
        console.error("Error sending OTP:", error);
        showStatusMessage(emailSection, `An error occurred: ${error.message}`, true);
    })
    .finally(() => {
        // Restore button state
        button.disabled = false;
        button.textContent = originalText;
    });
}

function verifyOTP() {
    const email = sessionStorage.getItem("resetEmail") || document.getElementById("forgotEmail").value;
    const otp = document.getElementById("otpCode").value;
    const otpSection = document.getElementById("otpSection");
    
    if (!otp) {
        showStatusMessage(otpSection, "Please enter the verification code.", true);
        return;
    }
    
    // Disable the button and show loading state
    const button = otpSection.querySelector("button");
    const originalText = button.textContent;
    button.disabled = true;
    button.textContent = "Verifying...";
    
    fetch("/verify-otp", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, otp }),
    })
    .then(response => {
        if (!response.ok) {
            throw new Error(`Server responded with status: ${response.status}`);
        }
        return response.json();
    })
    .then(data => {
        if (data.success) {
            // Show success message briefly
            showStatusMessage(otpSection, data.message);
            
            // Move to password reset step after a short delay
            setTimeout(() => {
                showResetStep('resetPasswordSection');
            }, 1000);
        } else {
            showStatusMessage(otpSection, data.message || "Invalid OTP.", true);
        }
    })
    .catch(error => {
        console.error("Error verifying OTP:", error);
        showStatusMessage(otpSection, `An error occurred: ${error.message}`, true);
    })
    .finally(() => {
        // Restore button state
        button.disabled = false;
        button.textContent = originalText;
    });
}

function resetPassword() {
    const email = sessionStorage.getItem("resetEmail") || document.getElementById("forgotEmail").value;
    const newPassword = document.getElementById("newPassword").value;
    const confirmPassword = document.getElementById("confirmPassword").value;
    const resetSection = document.getElementById("resetPasswordSection");
    
    if (!newPassword || !confirmPassword) {
        showStatusMessage(resetSection, "Please fill in all password fields.", true);
        return;
    }
    
    if (newPassword !== confirmPassword) {
        showStatusMessage(resetSection, "Passwords do not match!", true);
        return;
    }
    
    // Validate password strength
    const validation = validatePassword(newPassword);
    if (!validation.isValid) {
        showStatusMessage(resetSection, "Password doesn't meet requirements.", true);
        return;
    }
    
    // Disable the button and show loading state
    const button = resetSection.querySelector("button");
    const originalText = button.textContent;
    button.disabled = true;
    button.textContent = "Resetting...";
    
    fetch("/reset-password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, newPassword }),
    })
    .then(response => {
        if (!response.ok) {
            throw new Error(`Server responded with status: ${response.status}`);
        }
        return response.json();
    })
    .then(data => {
        if (data.success) {
            // Clear stored email
            sessionStorage.removeItem("resetEmail");
            
            // Show success step
            showResetStep('successSection');
            
            // Redirect to home page after a delay
            setTimeout(() => {
                window.location.href = "/";
            }, 3000);
        } else {
            showStatusMessage(resetSection, data.message || "Error resetting password.", true);
        }
    })
    .catch(error => {
        console.error("Error resetting password:", error);
        showStatusMessage(resetSection, `An error occurred: ${error.message}`, true);
    })
    .finally(() => {
        // Restore button state
        button.disabled = false;
        button.textContent = originalText;
    });
}

// Admin password reset functions
function showAdminResetStep(stepId) {
    const steps = document.querySelectorAll('.password-reset-step');
    steps.forEach(step => step.classList.remove('active-step'));
    document.getElementById(stepId).classList.add('active-step');
}

function resetAdminPasswordForm() {
    // Reset form fields
    document.getElementById('adminForgotPasswordForm').reset();
    
    if (document.getElementById('adminOtpCode')) {
        document.getElementById('adminOtpCode').value = '';
    }
    
    if (document.getElementById('adminNewPassword')) {
        document.getElementById('adminNewPassword').value = '';
    }
    
    if (document.getElementById('adminConfirmPassword')) {
        document.getElementById('adminConfirmPassword').value = '';
    }
    
    // Reset to first step
    showAdminResetStep('adminEmailSection');
}

function sendAdminOTP() {
    const email = document.getElementById('adminForgotEmail').value;
    const role = document.getElementById('adminForgotRole').value;
    
    if (!email || !role) {
        showMessage('Please enter your email and select your role', true);
        return;
    }
    
    // Disable the button and show loading state
    const button = document.querySelector('#adminEmailSection button');
    const originalText = button.textContent;
    button.disabled = true;
    button.textContent = "Sending...";
    
    fetch('/admin-send-otp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, role })
    })
    .then(response => {
        if (!response.ok) {
            return response.json().then(data => {
                throw new Error(data.message || `Server error: ${response.status}`);
            });
        }
        return response.json();
    })
    .then(data => {
        if (data.success) {
            // Store email for later use
            sessionStorage.setItem("adminResetEmail", email);
            sessionStorage.setItem("adminResetRole", role);
            
            // Show success message
            showMessage(data.message || "Verification code sent successfully!");
            
            // Move to OTP verification step
            showAdminResetStep('adminOtpSection');
        } else {
            showMessage(data.message || "Error sending verification code", true);
        }
    })
    .catch(error => {
        console.error('Error sending admin OTP:', error);
        showMessage(error.message || "Failed to send verification code", true);
    })
    .finally(() => {
        // Restore button state
        button.disabled = false;
        button.textContent = originalText;
    });
}

function verifyAdminOTP() {
    const email = sessionStorage.getItem("adminResetEmail");
    const otp = document.getElementById('adminOtpCode').value;
    
    if (!otp) {
        showMessage('Please enter the verification code', true);
        return;
    }
    
    // Disable the button and show loading state
    const button = document.querySelector('#adminOtpSection button');
    const originalText = button.textContent;
    button.disabled = true;
    button.textContent = "Verifying...";
    
    fetch('/admin-verify-otp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, otp })
    })
    .then(response => {
        if (!response.ok) {
            return response.json().then(data => {
                throw new Error(data.message || `Server error: ${response.status}`);
            });
        }
        return response.json();
    })
    .then(data => {
        if (data.success) {
            // Show success message
            showMessage(data.message || "Verification successful!");
            
            // Move to password reset step
            showAdminResetStep('adminResetPasswordSection');
        } else {
            showMessage(data.message || "Invalid verification code", true);
        }
    })
    .catch(error => {
        console.error('Error verifying admin OTP:', error);
        showMessage(error.message || "Failed to verify code", true);
    })
    .finally(() => {
        // Restore button state
        button.disabled = false;
        button.textContent = originalText;
    });
}

function resetAdminPassword() {
    const email = sessionStorage.getItem("adminResetEmail");
    const newPassword = document.getElementById('adminNewPassword').value;
    const confirmPassword = document.getElementById('adminConfirmPassword').value;
    
    if (!newPassword || !confirmPassword) {
        showMessage('Please enter and confirm your new password', true);
        return;
    }
    
    if (newPassword !== confirmPassword) {
        showMessage('Passwords do not match', true);
        return;
    }
    
    // Validate password strength
    const validation = validatePassword(newPassword);
    if (!validation.isValid) {
        showMessage(validation.message, true);
        return;
    }
    
    // Disable the button and show loading state
    const button = document.querySelector('#adminResetPasswordSection button');
    const originalText = button.textContent;
    button.disabled = true;
    button.textContent = "Resetting...";
    
    fetch('/admin-reset-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, newPassword })
    })
    .then(response => {
        if (!response.ok) {
            return response.json().then(data => {
                throw new Error(data.message || `Server error: ${response.status}`);
            });
        }
        return response.json();
    })
    .then(data => {
        if (data.success) {
            // Clear stored data
            sessionStorage.removeItem("adminResetEmail");
            sessionStorage.removeItem("adminResetRole");
            
            // Show success step
            showAdminResetStep('adminSuccessSection');
            
            // Redirect to login after a delay
            setTimeout(() => {
                const adminForgotPasswordModal = document.getElementById('adminForgotPasswordModal');
                const adminLoginModal = document.getElementById('adminLoginModal');
                if (adminForgotPasswordModal) adminForgotPasswordModal.style.display = 'none';
                if (adminLoginModal) adminLoginModal.style.display = 'flex';
                resetAdminPasswordForm();
            }, 3000);
        } else {
            showMessage(data.message || "Error resetting password", true);
        }
    })
    .catch(error => {
        console.error('Error resetting admin password:', error);
        showMessage(error.message || "Failed to reset password", true);
    })
    .finally(() => {
        button.disabled = false;
        button.textContent = originalText;
    });
}

let adminVerificationTimer;

function startAdminVerificationTimer() {
    let timeLeft = 60;
    const timerElement = document.getElementById('adminCodeTimer');
    const resendButton = document.getElementById('resendAdminCodeBtn');
    
    if (resendButton) resendButton.disabled = true;
    
    adminVerificationTimer = setInterval(() => {
        timeLeft--;
        if (timerElement) timerElement.textContent = timeLeft;
        
        if (timeLeft <= 0) {
            clearInterval(adminVerificationTimer);
            if (resendButton) resendButton.disabled = false;
            if (timerElement) timerElement.textContent = '0';
        }
    }, 1000);
}

function checkAdminAuth() {
    const isAdminLoggedIn = localStorage.getItem("isAdminLoggedIn") === "true";
    const adminToken = localStorage.getItem("adminToken");
    
    if (!isAdminLoggedIn) {
        window.location.href = '/';
        return false;
    }
    return true;
}

function handleAdminLogout() {
    fetch('/api/admin/logout', {
        method: 'POST',
        credentials: 'include'
    })
    .then(() => {
        localStorage.removeItem('isAdminLoggedIn');
        localStorage.removeItem('adminToken');
        localStorage.removeItem('adminRole');
        localStorage.removeItem('adminName');
        
        window.location.href = '/';
    })
    .catch(error => {
        console.error('Logout error:', error);
        showMessage('Logout failed. Please try again.', true);
    });
}

document.addEventListener('DOMContentLoaded', function() {

    setupPasswordToggle('signup-password');
    setupPasswordToggle('signup-confirm-password');
    
    setupPasswordToggle('newPassword');
    setupPasswordToggle('confirmPassword');
});
function setupPasswordToggle(passwordFieldId) {
    const passwordField = document.getElementById(passwordFieldId);
    if (!passwordField) return;
    
    let container = passwordField.parentElement;
    if (!container.classList.contains('password-container')) {
        container = document.createElement('div');
        container.className = 'password-container';
        
        passwordField.parentNode.insertBefore(container, passwordField);
        
        container.appendChild(passwordField);
    }

    let toggleBtn = container.querySelector('.toggle-password');
    if (!toggleBtn) {
        toggleBtn = document.createElement('button');
        toggleBtn.type = 'button';
        toggleBtn.className = 'toggle-password';
        toggleBtn.innerHTML = '<img src="/images/eye.png" alt="Show Password">';
        
        toggleBtn.addEventListener('click', function() {
            if (passwordField.type === 'password') {
                passwordField.type = 'text';
                this.querySelector('img').src = '/images/hidden.png';
                this.querySelector('img').alt = 'Hide Password';
            } else {
                passwordField.type = 'password';
                this.querySelector('img').src = '/images/eye.png';
                this.querySelector('img').alt = 'Show Password';
            }
        });
        
        container.appendChild(toggleBtn);
    }
    
    addPasswordToggleStyles();
}

function addPasswordToggleStyles() {
    if (document.getElementById('password-toggle-styles')) return;
    
    const style = document.createElement('style');
    style.id = 'password-toggle-styles';
    style.textContent = `
        .password-container {
            position: relative;
            display: flex;
            width: 100%;
            margin-bottom: 15px;
        }
        
        .password-container input {
            width: 100%;
            padding: 10px;
            padding-right: 40px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 14px;
            height: 40px;
            box-sizing: border-box;
        }
        
        .password-container .toggle-password {
            position: absolute;
            right: 10px;
            top: 50%;
            transform: translateY(-50%);
            background: none;
            border: none;
            cursor: pointer;
            padding: 0;
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 2;
            height: 40px;
            width: 40px;
        }
        
        .password-container .toggle-password img {
            width: 18px;
            height: 18px;
            object-fit: contain;
            opacity: 0.6;
            transition: opacity 0.2s;
        }
        
        .password-container .toggle-password:hover img {
            opacity: 1;
        }
        
        .password-container input:focus {
            outline: none;
            border-color: #f26523;
            box-shadow: 0 0 0 2px rgba(242, 101, 35, 0.1);
        }
    `;
    document.head.appendChild(style);
}

document.addEventListener('DOMContentLoaded', function() {
    const visaDisclaimerBtn = document.getElementById('visaDisclaimerBtn');
    const visaDisclaimerModal = document.getElementById('visaDisclaimerModal');
    const visaDisclaimerModalClose = document.getElementById('visaDisclaimerModalClose');
    
    if (visaDisclaimerBtn && visaDisclaimerModal && visaDisclaimerModalClose) {
        visaDisclaimerBtn.addEventListener('click', function() {
            visaDisclaimerModal.style.display = 'block';
            document.body.style.overflow = 'hidden';
        });

        visaDisclaimerModalClose.addEventListener('click', function() {
            visaDisclaimerModal.style.display = 'none';
            document.body.style.overflow = '';
        });
        
        visaDisclaimerModal.addEventListener('click', function(event) {
            if (event.target === visaDisclaimerModal) {
                visaDisclaimerModal.style.display = 'none';
                document.body.style.overflow = '';
            }
        });
        const modalContent = visaDisclaimerModal.querySelector('.disclaimer-modal-content');
        if (modalContent) {
            modalContent.addEventListener('click', function(event) {
                event.stopPropagation();
            });
        }
    }
});

document.addEventListener('DOMContentLoaded', function() {
    const insuranceModalBtn = document.getElementById('insuranceModalBtn');
    const insuranceModal = document.getElementById('insuranceModal');
    const insuranceModalClose = document.getElementById('insuranceModalClose');
    const insuranceQuoteForm = document.getElementById('insuranceQuoteForm');
    const quoteSuccess = document.getElementById('quoteSuccess');
    
    if (insuranceModalBtn && insuranceModal && insuranceModalClose) {
        insuranceModalBtn.addEventListener('click', function() {
            insuranceModal.style.display = 'block';
            document.body.style.overflow = 'hidden';
        });
        
        insuranceModalClose.addEventListener('click', function() {
            insuranceModal.style.display = 'none';
            document.body.style.overflow = '';
        });
        
        insuranceModal.addEventListener('click', function(event) {
            if (event.target === insuranceModal) {
                insuranceModal.style.display = 'none';
                document.body.style.overflow = '';
            }
        });
        
        const modalContent = insuranceModal.querySelector('.insurance-modal-content');
        if (modalContent) {
            modalContent.addEventListener('click', function(event) {
                event.stopPropagation();
            });
        }
        
        if (insuranceQuoteForm) {
            insuranceQuoteForm.addEventListener('submit', function(event) {
                event.preventDefault();
                
                insuranceQuoteForm.style.display = 'none';
                quoteSuccess.style.display = 'block';
                
                quoteSuccess.scrollIntoView({ behavior: 'smooth' });
                
                insuranceQuoteForm.reset();
                
                setTimeout(function() {
                    quoteSuccess.style.display = 'none';
                    insuranceQuoteForm.style.display = 'block';
                }, 10000);
            });
        }
        
        const today = new Date().toISOString().split('T')[0];
        const departureDateInput = document.getElementById('departureDate');
        const returnDateInput = document.getElementById('returnDate');
        
        if (departureDateInput) {
            departureDateInput.setAttribute('min', today);
            departureDateInput.addEventListener('change', function() {
                if (returnDateInput) {
                    returnDateInput.setAttribute('min', this.value);
                    returnDateInput.setAttribute('min', this.value);
                    
                    if (returnDateInput.value && returnDateInput.value < this.value) {
                        returnDateInput.value = this.value;
                    }
                }
            });
        }
    }
});

document.addEventListener('DOMContentLoaded', function() {
    const termsModal = document.getElementById('termsModal');
    const privacyModal = document.getElementById('privacyModal');
    const termsLink = document.getElementById('termsLink');
    const privacyLink = document.getElementById('privacyLink');
    const termsModalClose = document.getElementById('termsModalClose');
    const privacyModalClose = document.getElementById('privacyModalClose');
    const acceptTermsBtn = document.getElementById('acceptTermsBtn');
    const declineTermsBtn = document.getElementById('declineTermsBtn');
    const acceptPrivacyBtn = document.getElementById('acceptPrivacyBtn');
    const declinePrivacyBtn = document.getElementById('declinePrivacyBtn');
    
    function showModal(modal) {
        if (modal) {
            modal.style.display = 'block';
            document.body.style.overflow = 'hidden'; // Prevent scrolling behind modal
        }
    }
    
    // Function to hide modal
    function hideModal(modal) {
        if (modal) {
            modal.style.display = 'none';
            document.body.style.overflow = ''; // Restore scrolling
        }
    }
    
    // Open terms modal when link is clicked
    if (termsLink) {
        termsLink.addEventListener('click', function(e) {
            e.preventDefault();
            showModal(termsModal);
        });
    }
    
    // Open privacy modal when link is clicked
    if (privacyLink) {
        privacyLink.addEventListener('click', function(e) {
            e.preventDefault();
            showModal(privacyModal);
        });
    }
    
    // Close modals when close button is clicked
    if (termsModalClose) {
        termsModalClose.addEventListener('click', function() {
            hideModal(termsModal);
        });
    }
    
    if (privacyModalClose) {
        privacyModalClose.addEventListener('click', function() {
            hideModal(privacyModal);
        });
    }
    
    // Close modals when clicking outside
    window.addEventListener('click', function(event) {
        if (event.target === termsModal) {
            hideModal(termsModal);
        }
        if (event.target === privacyModal) {
            hideModal(privacyModal);
        }
    });
    
    // Handle accept terms button
    if (acceptTermsBtn) {
        acceptTermsBtn.addEventListener('click', function() {
            const checkbox = document.getElementById('terms-checkbox');
            if (checkbox) {
                checkbox.checked = true;
                const errorMsg = document.getElementById('terms-error');
                if (errorMsg) errorMsg.style.display = 'none';
            }
            hideModal(termsModal);
        });
    }
    
    // Handle decline terms button
    if (declineTermsBtn) {
        declineTermsBtn.addEventListener('click', function() {
            const checkbox = document.getElementById('terms-checkbox');
            if (checkbox) checkbox.checked = false;
            hideModal(termsModal);
        });
    }
    
    // Handle accept privacy button
    if (acceptPrivacyBtn) {
        acceptPrivacyBtn.addEventListener('click', function() {
            const checkbox = document.getElementById('terms-checkbox');
            if (checkbox) {
                checkbox.checked = true;
                const errorMsg = document.getElementById('terms-error');
                if (errorMsg) errorMsg.style.display = 'none';
            }
            hideModal(privacyModal);
        });
    }
    
    // Handle decline privacy button
    if (declinePrivacyBtn) {
        declinePrivacyBtn.addEventListener('click', function() {
            const checkbox = document.getElementById('terms-checkbox');
            if (checkbox) checkbox.checked = false;
            hideModal(privacyModal);
        });
    }
    
    // Modify the signup form submission to check for terms acceptance
    const signupForm = document.getElementById('signup-form');
    if (signupForm) {
        const originalSubmitHandler = signupForm.onsubmit;
        
        signupForm.onsubmit = function(e) {
            const termsCheckbox = document.getElementById('terms-checkbox');
            const termsError = document.getElementById('terms-error');
            
            if (termsCheckbox && !termsCheckbox.checked) {
                e.preventDefault();
                if (termsError) termsError.style.display = 'block';
                return false;
            }
            
            if (termsError) termsError.style.display = 'none';
            
            // Call the original submit handler if it exists
            if (typeof originalSubmitHandler === 'function') {
                return originalSubmitHandler.call(this, e);
            }
        };
    }
});
document.addEventListener('DOMContentLoaded', function() {
    const hamburgerMenu = document.querySelector('.hamburger-menu');
    const navMenu = document.querySelector('nav ul');
    const overlayBg = document.querySelector('.overlay-bg');
    
    // Check if we're on a page that needs the back button
    const needsBackButton = window.location.pathname.includes('/tours') || 
                           window.location.pathname.includes('/book-tour');
    
    if (needsBackButton) {
        document.querySelector('.back-button-wrapper').style.display = 'block';
        
        // Back button functionality
        const backButton = document.getElementById('backButton');
        if (backButton) {
            backButton.addEventListener('click', function() {
                history.back();
            });
        }
    }
    
    // Toggle mobile menu
    hamburgerMenu.addEventListener('click', function() {
        hamburgerMenu.classList.toggle('active');
        navMenu.classList.toggle('active');
        overlayBg.classList.toggle('active');
        
        // Prevent body scrolling when menu is open
        if (navMenu.classList.contains('active')) {
            document.body.style.overflow = 'hidden';
        } else {
            document.body.style.overflow = '';
        }
    });
    
    // Close menu when clicking outside
    overlayBg.addEventListener('click', function() {
        hamburgerMenu.classList.remove('active');
        navMenu.classList.remove('active');
        overlayBg.classList.remove('active');
        document.body.style.overflow = '';
    });
    
     const navLinks = document.querySelectorAll('nav ul li a');
    navLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            // Stop propagation for notification icon to prevent menu closing
            if (this.id === 'notificationIcon') {
                e.stopPropagation();
                return;
            }
            if (window.innerWidth <= 768) {
                hamburgerMenu.classList.remove('active');
                navMenu.classList.remove('active');
                overlayBg.classList.remove('active');
                document.body.style.overflow = '';
            }
        });
    });
    
    const dropdownTriggers = document.querySelectorAll('#notificationIcon, #profileIconWrapper');
    dropdownTriggers.forEach(trigger => {
        trigger.addEventListener('click', function(e) {
            e.stopPropagation();
            const dropdown = this.nextElementSibling;
            
            if (dropdown.style.display === 'block' || dropdown.classList.contains('show-mobile')) {
                dropdown.style.display = 'none';
                dropdown.classList.remove('show-mobile');
            } else {
                document.querySelectorAll('.dropdown-menu').forEach(menu => {
                    menu.style.display = 'none';
                    menu.classList.remove('show-mobile');
                });
                if (window.innerWidth <= 768) {
                    dropdown.classList.add('show-mobile');
                } else {
                    dropdown.style.display = 'block';
                }
            }
        });
    });
    
    document.addEventListener('click', function() {
        document.querySelectorAll('.dropdown-menu').forEach(menu => {
            menu.style.display = 'none';
        });
    });
    
    window.addEventListener('resize', function() {
        if (window.innerWidth > 768) {
            hamburgerMenu.classList.remove('active');
            navMenu.classList.remove('active');
            overlayBg.classList.remove('active');
            document.body.style.overflow = '';
        }
    });
});
document.addEventListener('DOMContentLoaded', function() {
    if (sessionStorage.getItem('isLoggedIn') === 'true') {
        document.getElementById('loginBtnWrapper').style.display = 'none';
        document.getElementById('userProfile').style.display = 'block';
        
        try {
            const userData = JSON.parse(sessionStorage.getItem('userData'));
            if (userData) {
                console.log('Restored user session from sessionStorage:', userData);
            }
        } catch (e) {
            console.error('Error parsing stored user data:', e);
        }
    }
    
    fetch('/check-auth')
        .then(response => response.json())
        .then(data => {
            if (data.isLoggedIn) {
                document.getElementById('loginBtnWrapper').style.display = 'none';
                document.getElementById('userProfile').style.display = 'block';
                
                sessionStorage.setItem('isLoggedIn', 'true');
            } else {
                if (sessionStorage.getItem('isLoggedIn') === 'true') {
                    console.log('Session mismatch - clearing stored session data');
                    sessionStorage.removeItem('isLoggedIn');
                    sessionStorage.removeItem('userData');
                }
                
                document.getElementById('loginBtnWrapper').style.display = 'block';
                document.getElementById('userProfile').style.display = 'none';
            }
        })
        .catch(error => {
            console.error('Error checking authentication status:', error);
        });
});
document.addEventListener('DOMContentLoaded', function() {
    const slides = document.querySelectorAll('.hero-slide');
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
document.addEventListener('DOMContentLoaded', function() {
    const signupBtn = document.getElementById('signupBtn');
    const adminLoginBtn = document.getElementById('adminLoginBtn');
    const signupBtnWrapper = document.getElementById('signupBtnWrapper');
    const adminLoginBtnWrapper = document.getElementById('adminLoginBtnWrapper');
    const loginBtnWrapper = document.getElementById('loginBtnWrapper');
    const signupModal = document.getElementById('signupModal');
    const adminLoginModal = document.getElementById('adminLoginModal');
    
    function checkUserLoggedIn() {
        const isLoggedIn = localStorage.getItem('userLoggedIn') === 'true';
        
        if (isLoggedIn) {
            loginBtnWrapper.style.display = 'none';
            signupBtnWrapper.style.display = 'none';
            adminLoginBtnWrapper.style.display = 'none';
            document.getElementById('userProfile').style.display = 'block';
            document.getElementById('notificationWrapper').style.display = 'block';
        } else {
            loginBtnWrapper.style.display = 'block';
            signupBtnWrapper.style.display = 'block';
            adminLoginBtnWrapper.style.display = 'block';
            document.getElementById('userProfile').style.display = 'none';
            document.getElementById('notificationWrapper').style.display = 'none';
        }
    }
    
    if (signupBtn) {
        signupBtn.addEventListener('click', function() {
            signupModal.style.display = 'block';
        });
    }
    
    if (adminLoginBtn) {
        adminLoginBtn.addEventListener('click', function() {
            adminLoginModal.style.display = 'block';
        });
    }
    
    checkUserLoggedIn();
    
    document.addEventListener('userLoggedIn', function() {
        localStorage.setItem('userLoggedIn', 'true');
        checkUserLoggedIn();
    });
    
    document.addEventListener('userLoggedOut', function() {
        localStorage.setItem('userLoggedIn', 'false');
        checkUserLoggedIn();
    });
    
    const logoutBtn = document.getElementById('logoutBtn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', function(e) {
            e.preventDefault();
            localStorage.setItem('userLoggedIn', 'false');
            
            document.dispatchEvent(new Event('userLoggedOut'));
            
            window.location.href = '/';
        });
    }
});
document.addEventListener('DOMContentLoaded', function() {
    const bookingSuccess = sessionStorage.getItem("bookingSuccess");
    if (bookingSuccess === "true") {
        sessionStorage.removeItem("bookingSuccess");
        
        const messageElement = document.createElement("div");
        messageElement.classList.add("success-popup");
        messageElement.textContent = "Your booking was successful!";
        document.body.appendChild(messageElement);
        setTimeout(() => messageElement.remove(), 5000);
    }
    
    const isLoggedIn = sessionStorage.getItem("isLoggedIn") === "true" || 
                       localStorage.getItem("isLoggedIn") === "true";
    
    if (isLoggedIn) {
        updateNavbarUI();
    }
});

function updateNavbarUI() {
    const isLoggedIn = sessionStorage.getItem("isLoggedIn") === "true" || 
                       localStorage.getItem("isLoggedIn") === "true";
    
    if (isLoggedIn) {
        const loginBtnWrapper = document.getElementById('loginBtnWrapper');
        const signupBtnWrapper = document.getElementById('signupBtnWrapper');
        const adminLoginBtnWrapper = document.getElementById('adminLoginBtnWrapper');
        
        if (loginBtnWrapper) loginBtnWrapper.style.display = 'none';
        if (signupBtnWrapper) signupBtnWrapper.style.display = 'none';
        if (adminLoginBtnWrapper) adminLoginBtnWrapper.style.display = 'none';
        
        const userProfile = document.getElementById('userProfile');
        if (userProfile) userProfile.style.display = 'block';
        
        const notificationWrapper = document.getElementById('notificationWrapper');
        if (notificationWrapper) notificationWrapper.style.display = 'block';
        
        fetchBookingStatus();
    } else {
        const loginBtnWrapper = document.getElementById('loginBtnWrapper');
        const signupBtnWrapper = document.getElementById('signupBtnWrapper');
        const adminLoginBtnWrapper = document.getElementById('adminLoginBtnWrapper');
        
        if (loginBtnWrapper) loginBtnWrapper.style.display = 'block';
        if (signupBtnWrapper) signupBtnWrapper.style.display = 'block';
        if (adminLoginBtnWrapper) adminLoginBtnWrapper.style.display = 'block';
        
        const userProfile = document.getElementById('userProfile');
        const notificationWrapper = document.getElementById('notificationWrapper');
        
        if (userProfile) userProfile.style.display = 'none';
        if (notificationWrapper) notificationWrapper.style.display = 'none';
    }
}
function fetchBookingStatus() {
    fetch('/api/user-notifications')
        .then(response => response.json())
        .then(data => {
            const bookingStatus = document.getElementById('bookingStatus');
            if (!bookingStatus) return;

            if (data.success && data.notifications) {
                const pendingBookings = data.notifications.filter(booking => booking.status === 'pending');
                
                if (pendingBookings.length > 0) {
                    bookingStatus.textContent = `You have ${pendingBookings.length} pending booking(s).`;
                } else {
                    bookingStatus.textContent = 'No current pending booking.';
                }
                if (data.newNotifications > 0) {
                    const notificationIcon = document.getElementById('notificationIcon');
                    if (notificationIcon) {
                        let badge = notificationIcon.querySelector('.notification-badge');
                        if (!badge) {
                            badge = document.createElement('span');
                            badge.className = 'notification-badge';
                            notificationIcon.appendChild(badge);
                        }
                        badge.textContent = data.newNotifications;
                    }
                }
            } else {
                bookingStatus.textContent = 'No current pending booking.';
            }
        })
        .catch(error => {
            console.error('Error checking notifications:', error);
            const bookingStatus = document.getElementById('bookingStatus');
            if (bookingStatus) {
                bookingStatus.textContent = 'Could not retrieve booking status.';
            }
        });
}
document.addEventListener('DOMContentLoaded', function() {
    const signupPassword = document.getElementById('signup-password');
    if (signupPassword) {
        signupPassword.addEventListener('input', function() {
            const password = this.value;
            const message = document.getElementById('signup-passwordMessage');
            const validation = validatePassword(password);
            
            if (validation.isValid) {
                message.style.color = 'green !important';
                message.setAttribute('data-valid', 'true');
            } else {
                message.style.color = 'red !important';
                message.removeAttribute('data-valid');
            }
            
            message.textContent = validation.message;
        });
    }
});
document.addEventListener('DOMContentLoaded', function() {
    const signupPassword = document.getElementById('signup-password');
    if (signupPassword) {
        signupPassword.addEventListener('input', function() {
            const password = this.value;
            const message = document.getElementById('signup-passwordMessage');
            const validation = validatePassword(password);
            
            message.className = 'error-message';
            message.style.backgroundColor = 'transparent';
            
            if (validation.isValid) {
                message.style.setProperty('color', 'green', 'important');
                message.classList.add('strong-password');
            } else {
                message.style.setProperty('color', 'red', 'important');
                message.classList.remove('strong-password');
            }
            
            message.textContent = validation.message;
        });
    }
});
const originalValidatePassword = validatePassword;
validatePassword = function(password) {
    const result = originalValidatePassword(password);
    if (result.isValid) {
        result.message = "✅ Strong password!";
    }
    
    return result;
};
document.addEventListener('DOMContentLoaded', function() {
    const adminPassword = document.getElementById('admin-password');
    if (adminPassword) {
        adminPassword.addEventListener('input', function() {
            const password = this.value;
            const message = document.getElementById('admin-passwordMessage');
            const validation = validatePassword(password);
            
            message.className = 'error-message';
            message.style.backgroundColor = 'transparent';
            
            if (validation.isValid) {
                message.style.setProperty('color', 'green', 'important');
                message.classList.add('strong-password');
            } else {
                message.style.setProperty('color', 'red', 'important');
                message.classList.remove('strong-password');
            }
            
            message.textContent = validation.message;
        });
    }
});
  document.addEventListener('DOMContentLoaded', function() {
    const requestAccountBtn = document.getElementById('requestAccountBtn');
    
    if (requestAccountBtn) {
        requestAccountBtn.addEventListener('click', function() {
            const adminLoginModal = document.getElementById('adminLoginModal');
            if (adminLoginModal) {
                adminLoginModal.style.display = 'none';
            }
            
            const adminSignupModal = document.getElementById('adminSignupModal');
            if (adminSignupModal) {
                adminSignupModal.style.display = 'block';
            }
        });
    }
    
    const switchToAdminLoginLink = document.getElementById('switchToAdminLoginLink');
    
    if (switchToAdminLoginLink) {
        switchToAdminLoginLink.addEventListener('click', function() {
            const adminSignupModal = document.getElementById('adminSignupModal');
            if (adminSignupModal) {
                adminSignupModal.style.display = 'none';
            }
            
            const adminLoginModal = document.getElementById('adminLoginModal');
            if (adminLoginModal) {
                adminLoginModal.style.display = 'block';
            }
        });
    }
});
document.addEventListener('DOMContentLoaded', function() {
    const adminPassword = document.getElementById('admin-password');
    if (adminPassword) {
        adminPassword.addEventListener('input', function() {
            const password = this.value;
            const message = document.getElementById('admin-passwordMessage');
            const validation = validatePassword(password);
            
            message.className = 'error-message';
            message.style.backgroundColor = 'transparent';
            
            if (validation.isValid) {
                message.style.setProperty('color', 'green', 'important');
                message.classList.add('strong-password');
            } else {
                message.style.setProperty('color', 'red', 'important');
                message.classList.remove('strong-password');
            }
            
            message.textContent = validation.message;
        });
    }
    
    const adminConfirmPassword = document.getElementById('admin-confirm-password');
    if (adminConfirmPassword) {
        adminConfirmPassword.addEventListener('input', function() {
            const password = document.getElementById('admin-password').value;
            const confirmPassword = this.value;
            const message = document.getElementById('admin-confirmPasswordMessage');
            
            if (password === confirmPassword && password.length > 0) {
                message.style.setProperty('color', 'green', 'important');
                message.textContent = '✔ Passwords match!';
            } else {
                message.style.setProperty('color', 'red', 'important');
                message.textContent = '❌ Passwords do not match.';
            }
        });
    }
});document.addEventListener('DOMContentLoaded', function() {
    const signupPassword = document.getElementById('signup-password');
    if (signupPassword) {
        signupPassword.addEventListener('input', function() {
            const password = this.value;
            const message = document.getElementById('signup-passwordMessage');
            const validation = validatePassword(password);
            
            message.className = 'error-message';
            message.style.backgroundColor = 'transparent';
            
            if (validation.isValid) {
                message.style.setProperty('color', 'green', 'important');
                message.classList.add('strong-password');
            } else {
                message.style.setProperty('color', 'red', 'important');
                message.classList.remove('strong-password');
            }
            
            message.textContent = validation.message;
        });
    }
    
    const signupConfirmPassword = document.getElementById('signup-confirm-password');
    if (signupConfirmPassword) {
        signupConfirmPassword.addEventListener('input', function() {
            const password = document.getElementById('signup-password').value;
            const confirmPassword = this.value;
            const message = document.getElementById('signup-confirmPasswordMessage');
            
            if (password === confirmPassword && password.length > 0) {
                message.style.setProperty('color', 'green', 'important');
                message.textContent = '✔ Passwords match!';
            } else {
                message.style.setProperty('color', 'red', 'important');
                message.textContent = '❌ Passwords do not match.';
            }
        });
    }
});document.addEventListener('DOMContentLoaded', function() {
    const termsModal = document.getElementById('termsModal');
    const privacyModal = document.getElementById('privacyModal');
    const termsLink = document.getElementById('termsLink');
    const privacyLink = document.getElementById('privacyLink');
    const adminTermsLink = document.getElementById('adminTermsLink');
    const adminPrivacyLink = document.getElementById('adminPrivacyLink');
    const termsModalClose = document.getElementById('termsModalClose');
    const privacyModalClose = document.getElementById('privacyModalClose');
    const acceptTermsBtn = document.getElementById('acceptTermsBtn');
    const declineTermsBtn = document.getElementById('declineTermsBtn');
    const acceptPrivacyBtn = document.getElementById('acceptPrivacyBtn');
    const declinePrivacyBtn = document.getElementById('declinePrivacyBtn');
    
    function showModal(modal) {
        if (modal) {
            modal.style.display = 'block';
            document.body.style.overflow = 'hidden';
        }
    }
    
    function hideModal(modal) {
        if (modal) {
            modal.style.display = 'none';
            document.body.style.overflow = '';
        }
    }
    
    let currentForm = null;
    
    if (termsLink) {
        termsLink.addEventListener('click', function(e) {
            e.preventDefault();
            currentForm = 'user';
            showModal(termsModal);
        });
    }
    
    if (privacyLink) {
        privacyLink.addEventListener('click', function(e) {
            e.preventDefault();
            currentForm = 'user';
            showModal(privacyModal);
        });
    }
    
    if (adminTermsLink) {
        adminTermsLink.addEventListener('click', function(e) {
            e.preventDefault();
            currentForm = 'admin';
            showModal(termsModal);
        });
    }
    
    if (adminPrivacyLink) {
        adminPrivacyLink.addEventListener('click', function(e) {
            e.preventDefault();
            currentForm = 'admin';
            showModal(privacyModal);
        });
    }
    
    if (termsModalClose) {
        termsModalClose.addEventListener('click', function() {
            hideModal(termsModal);
        });
    }
    
    if (privacyModalClose) {
        privacyModalClose.addEventListener('click', function() {
            hideModal(privacyModal);
        });
    }
    
    // Close modals when clicking outside
    window.addEventListener('click', function(event) {
        if (event.target === termsModal) {
            hideModal(termsModal);
        }
        if (event.target === privacyModal) {
            hideModal(privacyModal);
        }
    });
    
    // Handle accept terms button
    if (acceptTermsBtn) {
        acceptTermsBtn.addEventListener('click', function() {
            const checkbox = currentForm === 'admin' ? 
                document.getElementById('admin-terms-checkbox') : 
                document.getElementById('terms-checkbox');
                
            const errorMsg = currentForm === 'admin' ? 
                document.getElementById('admin-terms-error') : 
                document.getElementById('terms-error');
                
            if (checkbox) {
                checkbox.checked = true;
                if (errorMsg) errorMsg.style.display = 'none';
            }
            hideModal(termsModal);
        });
    }
    
    // Handle decline terms button
    if (declineTermsBtn) {
        declineTermsBtn.addEventListener('click', function() {
            const checkbox = currentForm === 'admin' ? 
                document.getElementById('admin-terms-checkbox') : 
                document.getElementById('terms-checkbox');
                
            if (checkbox) checkbox.checked = false;
            hideModal(termsModal);
        });
    }
    
    // Handle accept privacy button
    if (acceptPrivacyBtn) {
        acceptPrivacyBtn.addEventListener('click', function() {
            const checkbox = currentForm === 'admin' ? 
                document.getElementById('admin-terms-checkbox') : 
                document.getElementById('terms-checkbox');
                
            const errorMsg = currentForm === 'admin' ? 
                document.getElementById('admin-terms-error') : 
                document.getElementById('terms-error');
                
            if (checkbox) {
                checkbox.checked = true;
                if (errorMsg) errorMsg.style.display = 'none';
            }
            hideModal(privacyModal);
        });
    }
    
    // Handle decline privacy button
    if (declinePrivacyBtn) {
        declinePrivacyBtn.addEventListener('click', function() {
            const checkbox = currentForm === 'admin' ? 
                document.getElementById('admin-terms-checkbox') : 
                document.getElementById('terms-checkbox');
                
            if (checkbox) checkbox.checked = false;
            hideModal(privacyModal);
        });
    }
    
    // Modify the signup form submission to check for terms acceptance
    const signupForm = document.getElementById('signup-form');
    if (signupForm) {
        signupForm.addEventListener('submit', function(e) {
            const termsCheckbox = document.getElementById('terms-checkbox');
            const termsError = document.getElementById('terms-error');
            
            if (termsCheckbox && !termsCheckbox.checked) {
                e.preventDefault();
                if (termsError) termsError.style.display = 'block';
                return false;
            }
            
            if (termsError) termsError.style.display = 'none';
        });
    }
    
    // Modify the admin signup form submission to check for terms acceptance
    const adminSignupForm = document.getElementById('admin-signup-form');
    if (adminSignupForm) {
        adminSignupForm.addEventListener('submit', function(e) {
            const termsCheckbox = document.getElementById('admin-terms-checkbox');
            const termsError = document.getElementById('admin-terms-error');
            
            if (termsCheckbox && !termsCheckbox.checked) {
                e.preventDefault();
                if (termsError) termsError.style.display = 'block';
                return false;
            }
            
            if (termsError) termsError.style.display = 'none';
        });
    }
});
document.addEventListener('DOMContentLoaded', function() {
    const adminSignupForm = document.getElementById('admin-signup-form');
    if (adminSignupForm) {
        // Replace the existing submit handler with one that doesn't check for terms
        adminSignupForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            // Get form data
            const firstName = document.getElementById('admin-firstName').value.trim();
            const lastName = document.getElementById('admin-lastName').value.trim();
            const username = document.getElementById('admin-username').value.trim();
            const email = document.getElementById('admin-email').value.trim();
            const phoneNumber = document.getElementById('admin-phoneNumber').value.trim();
            const role = document.getElementById('admin-role').value;
            const password = document.getElementById('admin-password').value;
            const confirmPassword = document.getElementById('admin-confirm-password').value;
            const verificationCode = document.getElementById('admin-verification-code')?.value.trim();
            
            // Form validation
            if (!firstName || !lastName || !username || !email || !phoneNumber || !role || !password || !confirmPassword) {
                showMessage("Please fill in all required fields.", true);
                return;
            }
            
            // Check password validity
            const passwordValidation = validatePassword(password);
            if (!passwordValidation.isValid) {
                showMessage(passwordValidation.message, true);
                return;
            }
            
            if (password !== confirmPassword) {
                showMessage('Passwords do not match.', true);
                return;
            }
            
            // Check if verification section is visible but code wasn't entered
            const verificationSection = document.getElementById('admin-verification-section');
            const verificationSectionVisible = verificationSection && verificationSection.style.display !== 'none';
            
            if (verificationSectionVisible && !verificationCode) {
                showMessage('Please enter the verification code sent to your email.', true);
                return;
            }
            
            // Show loading state
            const submitBtn = this.querySelector('button[type="submit"]');
            const originalBtnText = submitBtn.textContent;
            submitBtn.disabled = true;
            submitBtn.textContent = "Submitting...";
            
            // Prepare data for submission
            const userData = {
                firstName,
                lastName,
                username,
                email,
                phoneNumber,
                role,
                password,
                verificationCode: verificationCode || null
            };
            
            // Submit the form data
            fetch('/admin-signup', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(userData)
            })
            .then(response => {
                if (!response.ok) {
                    return response.json().then(data => {
                        throw new Error(data.message || `Server error: ${response.status}`);
                    });
                }
                return response.json();
            })
            .then(data => {
                if (data.success) {
                    // Close the signup modal
                    const adminSignupModal = document.getElementById('adminSignupModal');
                    if (adminSignupModal) {
                        adminSignupModal.style.display = 'none';
                    }
                    
                    // Show the pending approval modal
                    const accountPendingModal = document.getElementById('accountPendingModal');
                    if (accountPendingModal) {
                        accountPendingModal.style.display = 'block';
                    }
                    
                    // Reset the form
                    this.reset();
                } else {
                    showMessage(`Signup failed: ${data.message || 'Unknown error'}`, true);
                }
            })
            .catch(error => {
                console.error('Admin signup error:', error);
                showMessage(error.message || "Signup failed. Please try again.", true);
            })
            .finally(() => {
                // Restore button state
                submitBtn.disabled = false;
                submitBtn.textContent = originalBtnText;
            });
        });
    }
    
    // Update the Terms and Conditions modal handler to exclude admin form
    const termsModal = document.getElementById('termsModal');
    const privacyModal = document.getElementById('privacyModal');
    
    // Get the links that open the modals for user signup only
    const termsLink = document.getElementById('termsLink');
    const privacyLink = document.getElementById('privacyLink');
    
    // Remove the admin terms links from the event listeners
    if (termsLink) {
        termsLink.addEventListener('click', function(e) {
            e.preventDefault();
            if (termsModal) termsModal.style.display = 'block';
        });
    }
    
    if (privacyLink) {
        privacyLink.addEventListener('click', function(e) {
            e.preventDefault();
            if (privacyModal) privacyModal.style.display = 'block';
        });
    }
});document.addEventListener('DOMContentLoaded', function() {
    // Get the notification icon element
    const notificationIcon = document.getElementById('notificationIcon');
    const notificationDropdown = document.getElementById('notificationDropdown');
    
    // Add click event listener to the notification icon
    if (notificationIcon) {
        notificationIcon.addEventListener('click', function(e) {
            e.preventDefault();
            e.stopPropagation();
            
            // Toggle the dropdown visibility
            if (notificationDropdown) {
                if (notificationDropdown.style.display === 'block') {
                    notificationDropdown.style.display = 'none';
                } else {
                    notificationDropdown.style.display = 'block';
                }
            }
        });
    }
    
    // Close dropdown when clicking outside
    document.addEventListener('click', function(e) {
        if (notificationDropdown && 
            notificationIcon && 
            !notificationIcon.contains(e.target) && 
            !notificationDropdown.contains(e.target)) {
            notificationDropdown.style.display = 'none';
        }
    });
    
    // Check if user is logged in and show notification bell
    const isLoggedIn = localStorage.getItem('isLoggedIn') === 'true' || 
                       sessionStorage.getItem('isLoggedIn') === 'true';
    
    if (isLoggedIn) {
        const notificationWrapper = document.getElementById('notificationWrapper');
        if (notificationWrapper) {
            notificationWrapper.style.display = 'block';
        }
    }
});

document.addEventListener('DOMContentLoaded', function() {
    const observerOptions = {
        threshold: 0.2,
        rootMargin: '0px 0px -50px 0px'
    };

    const servicesObserver = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('animate-in');
                
                // Trigger staggered animations for service cards
                const cards = entry.target.querySelectorAll('.service-card');
                cards.forEach((card, index) => {
                    setTimeout(() => {
                        card.style.opacity = '1';
                        card.style.transform = 'translateY(0)';
                    }, index * 100);
                });
            }
        });
    }, observerOptions);

    // Observe the services section
    const servicesSection = document.querySelector('.services-section');
    if (servicesSection) {
        servicesObserver.observe(servicesSection);
    }

    // Click-based expansion for service cards
    const serviceCards = document.querySelectorAll('.service-card');
    serviceCards.forEach((card, index) => {
        // Add click event listener
        card.addEventListener('click', function(e) {
            e.preventDefault();
            e.stopPropagation();
            
            // Toggle expanded state
            const isExpanded = this.classList.contains('expanded');
            
            // Close all other expanded cards first
            serviceCards.forEach(otherCard => {
                if (otherCard !== this) {
                    otherCard.classList.remove('expanded');
                }
            });
            
            // Toggle current card
            if (isExpanded) {
                this.classList.remove('expanded');
            } else {
                this.classList.add('expanded');
                
                // Smooth scroll to card if it's not fully visible
                setTimeout(() => {
                    const cardRect = this.getBoundingClientRect();
                    const windowHeight = window.innerHeight;
                    
                    if (cardRect.bottom > windowHeight - 50) {
                        this.scrollIntoView({
                            behavior: 'smooth',
                            block: 'center'
                        });
                    }
                }, 300);
            }
        });
        
        // Add keyboard support for accessibility
        card.setAttribute('tabindex', '0');
        card.setAttribute('role', 'button');
        card.setAttribute('aria-expanded', 'false');
        
        card.addEventListener('keydown', function(e) {
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                this.click();
            }
        });
        
        const observer = new MutationObserver(function(mutations) {
            mutations.forEach(function(mutation) {
                if (mutation.type === 'attributes' && mutation.attributeName === 'class') {
                    const isExpanded = card.classList.contains('expanded');
                    card.setAttribute('aria-expanded', isExpanded.toString());
                }
            });
        });
        
        observer.observe(card, { attributes: true });
    });

    // Close expanded cards when clicking outside
    document.addEventListener('click', function(e) {
        if (!e.target.closest('.service-card')) {
            serviceCards.forEach(card => {
                card.classList.remove('expanded');
            });
        }
    });

    // Handle escape key to close expanded cards
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') {
            serviceCards.forEach(card => {
                card.classList.remove('expanded');
            });
        }
    });

    // Smooth scroll to services section when clicking services nav link
    const servicesNavLink = document.querySelector('a[href="#services"]');
    if (servicesNavLink) {
        servicesNavLink.addEventListener('click', function(e) {
            e.preventDefault();
            const servicesSection = document.querySelector('#services');
            if (servicesSection) {
                servicesSection.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    }

    let ticking = false;
    
    function updateScrollAnimations() {
        ticking = false;
    }
    
    window.addEventListener('scroll', function() {
        if (!ticking) {
            requestAnimationFrame(updateScrollAnimations);
            ticking = true;
        }
    });
    window.addEventListener('resize', function() {
        serviceCards.forEach(card => {
            card.classList.remove('expanded');
        });
    });
});
// Modern Testimonials Functionality
class ModernTestimonials {
    constructor() {
        this.currentSlide = 0;
        this.testimonials = [];
        this.autoPlayInterval = null;
        this.isAnimating = false;
        
        this.init();
    }
    
    async init() {
        await this.fetchTestimonials();
        this.setupCarousel();
        this.setupEventListeners();
        this.startAutoPlay();
        this.setupIntersectionObserver();
    }
    
    async fetchTestimonials() {
        const loadingElement = document.getElementById('testimonialsLoading');
        const carouselElement = document.getElementById('testimonialsCarousel');
        
        if (loadingElement) loadingElement.style.display = 'block';
        if (carouselElement) carouselElement.style.display = 'none';
        
        try {
            const response = await fetch('/api/feedback');
            if (!response.ok) throw new Error('Failed to fetch testimonials');
            
            const data = await response.json();
            
            if (data.success && data.feedback.length > 0) {
                this.testimonials = data.feedback;
                this.renderTestimonials();
                this.setupIndicators();
                
                if (loadingElement) loadingElement.style.display = 'none';
                if (carouselElement) carouselElement.style.display = 'block';
            } else {
                this.showNoTestimonials();
            }
        } catch (error) {
            console.error('Error fetching testimonials:', error);
            this.showError();
        }
    }
    
    renderTestimonials() {
        const track = document.getElementById('testimonialsTrack');
        if (!track) return;
        
        track.innerHTML = '';
        
        this.testimonials.forEach((testimonial, index) => {
            const card = this.createTestimonialCard(testimonial, index);
            track.appendChild(card);
        });
        
        this.updateActiveCard();
    }
    
    createTestimonialCard(testimonial, index) {
        const card = document.createElement('div');
        card.className = `modern-testimonial-card ${index === 0 ? 'active' : ''}`;
        card.setAttribute('data-index', index);
        
        const date = new Date(testimonial.date).toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'long',
            day: 'numeric'
        });
        
        const country = testimonial.country || 'International Client';
        const countryFlag = this.getCountryFlag(country);
        const initials = this.getInitials(testimonial.name);
        
        card.innerHTML = `
            <div class="testimonial-quote-icon">"</div>
            <div class="testimonial-content">
                <p class="testimonial-text">${testimonial.message}</p>
            </div>
            <div class="testimonial-author">
                <div class="author-avatar">${initials}</div>
                <div class="author-info">
                    <div class="author-name">${testimonial.name}</div>
                    <div class="author-country">
                        <span class="country-flag">${countryFlag}</span>
                        ${country}
                    </div>
                    <div class="testimonial-date">${date}</div>
                </div>
            </div>
        `;
        
        return card;
    }
    
    getInitials(name) {
        return name.split(' ').map(n => n[0]).join('').toUpperCase().slice(0, 2);
    }
    
    getCountryFlag(country) {
        const flags = {
            'Philippines': '🇵🇭',
            'United States': '🇺🇸',
            'Canada': '🇨🇦',
            'Australia': '🇦🇺',
            'United Kingdom': '🇬🇧',
            'Japan': '🇯🇵',
            'South Korea': '🇰🇷',
            'Singapore': '🇸🇬',
            'Malaysia': '🇲🇾',
            'Thailand': '🇹🇭',
            'Indonesia': '🇮🇩',
            'Vietnam': '🇻🇳',
            'India': '🇮🇳',
            'China': '🇨🇳',
            'Germany': '🇩🇪',
            'France': '🇫🇷',
            'Italy': '🇮🇹',
            'Spain': '🇪🇸',
            'Netherlands': '🇳🇱',
            'Switzerland': '🇨🇭',
            'Sweden': '🇸🇪',
            'Norway': '🇳🇴',
            'Denmark': '🇩🇰',
            'Brazil': '🇧🇷',
            'Mexico': '🇲🇽',
            'Argentina': '🇦🇷',
            'Chile': '🇨🇱',
            'South Africa': '🇿🇦',
            'Egypt': '🇪🇬',
            'UAE': '🇦🇪',
            'Saudi Arabia': '🇸🇦',
            'Turkey': '🇹🇷',
            'Russia': '🇷🇺',
            'New Zealand': '🇳🇿'
        };
        return flags[country] || '🌍';
    }
    
    setupIndicators() {
        const indicatorsContainer = document.getElementById('carouselIndicators');
        if (!indicatorsContainer) return;
        
        indicatorsContainer.innerHTML = '';
        
        this.testimonials.forEach((_, index) => {
            const indicator = document.createElement('div');
            indicator.className = `indicator ${index === 0 ? 'active' : ''}`;
            indicator.setAttribute('data-index', index);
            indicator.addEventListener('click', () => this.goToSlide(index));
            indicatorsContainer.appendChild(indicator);
        });
    }
    
    setupEventListeners() {
        const prevBtn = document.getElementById('prevBtn');
        const nextBtn = document.getElementById('nextBtn');
        
        if (prevBtn) prevBtn.addEventListener('click', () => this.previousSlide());
        if (nextBtn) nextBtn.addEventListener('click', () => this.nextSlide());
        
        this.setupTouchEvents();
        document.addEventListener('keydown', (e) => {
            if (e.key === 'ArrowLeft') this.previousSlide();
            if (e.key === 'ArrowRight') this.nextSlide();
        });
        
        // Pause autoplay on hover
        const carousel = document.getElementById('testimonialsCarousel');
        if (carousel) {
            carousel.addEventListener('mouseenter', () => this.pauseAutoPlay());
            carousel.addEventListener('mouseleave', () => this.startAutoPlay());
        }
    }
    
    setupTouchEvents() {
        const track = document.getElementById('testimonialsTrack');
        if (!track) return;
        
        let startX = 0;
        let currentX = 0;
        let isDragging = false;
        
        track.addEventListener('touchstart', (e) => {
            startX = e.touches[0].clientX;
            isDragging = true;
            this.pauseAutoPlay();
        });
        
        track.addEventListener('touchmove', (e) => {
            if (!isDragging) return;
            currentX = e.touches[0].clientX;
        });
        
        track.addEventListener('touchend', () => {
            if (!isDragging) return;
            isDragging = false;
            
            const diff = startX - currentX;
            if (Math.abs(diff) > 50) {
                if (diff > 0) {
                    this.nextSlide();
                } else {
                    this.previousSlide();
                }
            }
            
            this.startAutoPlay();
        });
    }
    
    goToSlide(index) {
        if (this.isAnimating || index === this.currentSlide) return;
        
        this.isAnimating = true;
        this.currentSlide = index;
        
        const track = document.getElementById('testimonialsTrack');
        if (track) {
            track.style.transform = `translateX(-${index * 100}%)`;
        }
        
        this.updateActiveCard();
        this.updateIndicators();
        
        setTimeout(() => {
            this.isAnimating = false;
        }, 600);
    }
    
    nextSlide() {
        const nextIndex = (this.currentSlide + 1) % this.testimonials.length;
        this.goToSlide(nextIndex);
    }
    previousSlide() {
        const prevIndex = this.currentSlide === 0 ? this.testimonials.length - 1 : this.currentSlide - 1;
        this.goToSlide(prevIndex);
    }
    
    updateActiveCard() {
        const cards = document.querySelectorAll('.modern-testimonial-card');
        cards.forEach((card, index) => {
            card.classList.toggle('active', index === this.currentSlide);
        });
    }
    
    updateIndicators() {
        const indicators = document.querySelectorAll('.indicator');
        indicators.forEach((indicator, index) => {
            indicator.classList.toggle('active', index === this.currentSlide);
        });
    }
    
    setupCarousel() {
        const track = document.getElementById('testimonialsTrack');
        if (!track) return;
        
        // Set initial position
        track.style.transform = 'translateX(0%)';
        
        // Add smooth transition
        track.style.transition = 'transform 0.6s cubic-bezier(0.25, 0.46, 0.45, 0.94)';
    }
    
    startAutoPlay() {
        this.pauseAutoPlay(); // Clear any existing interval
        this.autoPlayInterval = setInterval(() => {
            this.nextSlide();
        }, 5000); // Change slide every 5 seconds
    }
    
    pauseAutoPlay() {
        if (this.autoPlayInterval) {
            clearInterval(this.autoPlayInterval);
            this.autoPlayInterval = null;
        }
    }
    
    setupIntersectionObserver() {
        const section = document.querySelector('.modern-testimonials-section');
        if (!section) return;
        
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    // Trigger animations when section comes into view
                    this.animateOnScroll();
                    observer.unobserve(entry.target);
                }
            });
        }, {
            threshold: 0.2
        });
        
        observer.observe(section);
    }
    
    animateOnScroll() {
        // Add staggered animations to elements
        const elements = document.querySelectorAll('[data-aos]');
        elements.forEach((element, index) => {
            setTimeout(() => {
                element.classList.add('aos-animate');
            }, index * 100);
        });
        
        // Animate floating elements
        const floatingElements = document.querySelectorAll('.floating-star, .floating-quote');
        floatingElements.forEach((element, index) => {
            setTimeout(() => {
                element.style.animation = `floatRandom 15s ease-in-out infinite ${index * 2}s`;
            }, index * 500);
        });
    }
    
    showNoTestimonials() {
        const track = document.getElementById('testimonialsTrack');
        const loadingElement = document.getElementById('testimonialsLoading');
        const carouselElement = document.getElementById('testimonialsCarousel');
        
        if (loadingElement) loadingElement.style.display = 'none';
        if (carouselElement) carouselElement.style.display = 'none';
        
        if (track) {
            track.innerHTML = `
                <div class="no-testimonials-message">
                    <div class="no-testimonials-icon">💬</div>
                    <h3>No Testimonials Yet</h3>
                    <p>Be the first to share your experience with us!</p>
                </div>
            `;
        }
    }
    
    showError() {
        const track = document.getElementById('testimonialsTrack');
        const loadingElement = document.getElementById('testimonialsLoading');
        const carouselElement = document.getElementById('testimonialsCarousel');
        
        if (loadingElement) loadingElement.style.display = 'none';
        if (carouselElement) carouselElement.style.display = 'none';
        
        if (track) {
            track.innerHTML = `
                <div class="testimonials-error">
                    <div class="error-icon">⚠️</div>
                    <h3>Unable to Load Testimonials</h3>
                    <p>Please try refreshing the page.</p>
                    <button onclick="location.reload()" class="retry-btn">Retry</button>
                </div>
            `;
        }
    }
}

// Initialize the modern testimonials when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    new ModernTestimonials();
});
