document.addEventListener('DOMContentLoaded', () => {
    const adminUsernameInput = document.getElementById('admin-username');
    if (!adminUsernameInput) return;

    const messageEl = document.createElement('p');
    messageEl.id = 'adminUsernameAvailabilityMessage';
    messageEl.style.marginTop = '5px';
    messageEl.style.fontSize = '14px';
    adminUsernameInput.insertAdjacentElement('afterend', messageEl);

    let timeout = null;

    adminUsernameInput.addEventListener('input', () => {
        clearTimeout(timeout);
        const username = adminUsernameInput.value.trim();
        messageEl.textContent = '';
        if (!username) return;

        // debounce requests
        timeout = setTimeout(async () => {
            try {
                const res = await fetch(`/check-admin-username?username=${encodeURIComponent(username)}`);
                const data = await res.json();

                if (data.available) {
                    messageEl.textContent = '✅ Username available';
                    messageEl.style.color = 'green';
                } else {
                    messageEl.textContent = '❌ ' + (data.message || 'Username not available');
                    messageEl.style.color = 'red';
                }
            } catch (err) {
                console.error('Error checking admin username:', err);
                messageEl.textContent = '⚠️ Could not check username';
                messageEl.style.color = 'orange';
            }
        }, 500);
    });
});
