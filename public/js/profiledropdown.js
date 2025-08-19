// profile-dropdown.js - Simple standalone script for profile dropdown

(function() {
    // Wait for DOM to be fully loaded
    document.addEventListener('DOMContentLoaded', function() {
        console.log("Profile dropdown script loaded");
        
        // Direct DOM manipulation for profile visibility (for testing)
        const userProfile = document.getElementById('userProfile');
        if (userProfile) {
            userProfile.style.display = 'block';
        }
        
        // Get profile elements
        const profileIcon = document.getElementById('profileIconWrapper');
        const profileDropdown = document.getElementById('profileDropdown');
        
        // Remove any existing event listeners by cloning and replacing
        if (profileIcon) {
            const newProfileIcon = profileIcon.cloneNode(true);
            profileIcon.parentNode.replaceChild(newProfileIcon, profileIcon);
            
            // Add click handler to the new element
            newProfileIcon.addEventListener('click', function(e) {
                e.preventDefault();
                e.stopPropagation();
                console.log("Profile icon clicked");
                
                // Toggle dropdown
                if (profileDropdown) {
                    if (profileDropdown.style.display === 'block') {
                        profileDropdown.style.display = 'none';
                    } else {
                        profileDropdown.style.display = 'block';
                    }
                }
            });
        }
        
        // Prevent dropdown clicks from closing it
        if (profileDropdown) {
            profileDropdown.addEventListener('click', function(e) {
                e.stopPropagation();
            });
        }
        
        // Close dropdown when clicking elsewhere
        document.addEventListener('click', function() {
            if (profileDropdown) {
                profileDropdown.style.display = 'none';
            }
        });
    });
})();
