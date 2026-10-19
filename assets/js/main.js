// Animate the risk score gauge on the result page
document.addEventListener('DOMContentLoaded', () => {
    const gauge = document.querySelector('.gauge');
    if (!gauge) return;

    const score = Number(gauge.dataset.score);
    const fill = gauge.querySelector('.gauge-fill');
    const value = gauge.querySelector('.gauge-value');
    const circumference = 2 * Math.PI * 52;

    requestAnimationFrame(() => {
        fill.style.strokeDashoffset = circumference * (1 - score / 100);
    });

    const start = performance.now();
    const tick = (now) => {
        const progress = Math.min((now - start) / 1000, 1);
        value.textContent = Math.round(score * progress);
        if (progress < 1) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
});

// Live character counter for the report details box
document.addEventListener('DOMContentLoaded', () => {
    const reason = document.getElementById('reason');
    const counter = document.getElementById('reasonCount');
    if (!reason || !counter) return;

    reason.addEventListener('input', () => {
        counter.textContent = reason.value.length;
    });
});

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
