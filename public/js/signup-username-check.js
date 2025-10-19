document.addEventListener('DOMContentLoaded', () => {
    const usernameInput = document.getElementById('signup-username');
    if (!usernameInput) return;

    const messageEl = document.createElement('p');
    messageEl.id = 'usernameAvailabilityMessage';
    messageEl.style.marginTop = '5px';
    messageEl.style.fontSize = '14px';
    usernameInput.insertAdjacentElement('afterend', messageEl);

    let timeout = null;

    usernameInput.addEventListener('input', () => {
        clearTimeout(timeout);
        const username = usernameInput.value.trim();
        messageEl.textContent = '';
        if (!username) return;

        // debounce so we don’t hammer the server
        timeout = setTimeout(async () => {
            try {
                const res = await fetch(`/check-username?username=${encodeURIComponent(username)}`);
                const data = await res.json();

                if (data.available) {
                    messageEl.textContent = '✅ Username available';
                    messageEl.style.color = 'green';
                } else {
                    messageEl.textContent = '❌ ' + (data.message || 'Username not available');
                    messageEl.style.color = 'red';
                }
            } catch (err) {
                console.error('Error checking username:', err);
                messageEl.textContent = '⚠️ Could not check username';
                messageEl.style.color = 'orange';
            }
        }, 500); // 0.5 s delay
    });
});
