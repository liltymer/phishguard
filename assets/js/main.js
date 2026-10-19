// Client-side check before the URL is sent to the server
document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('scanForm');
    if (!form) return;

    const input = document.getElementById('urlInput');
    const error = document.getElementById('urlError');

    form.addEventListener('submit', (event) => {
        let value = input.value.trim();

        if (value === '') {
            event.preventDefault();
            showError('Please enter a URL to scan.');
            return;
        }

        // Allow "example.com" by assuming http:// when no scheme is given
        if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) {
            value = 'http://' + value;
        }

        try {
            const parsed = new URL(value);
            if (!parsed.hostname.includes('.') && !/^\d+$/.test(parsed.hostname)) {
                throw new Error('no dot');
            }
        } catch {
            event.preventDefault();
            showError('That does not look like a valid URL.');
            return;
        }

        input.value = value;
    });

    input.addEventListener('input', () => error.classList.add('d-none'));

    function showError(message) {
        error.textContent = message;
        error.classList.remove('d-none');
        input.focus();
    }
});
