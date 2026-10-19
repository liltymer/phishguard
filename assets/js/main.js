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

// Ask before destructive admin actions: <button data-confirm="Are you sure?">
document.addEventListener('click', (event) => {
    const button = event.target.closest('[data-confirm]');
    if (button && !window.confirm(button.dataset.confirm)) {
        event.preventDefault();
    }
});

// Dashboard chart tooltip: shows each day's breakdown on hover or keyboard focus
document.addEventListener('DOMContentLoaded', () => {
    const chart = document.querySelector('.chart');
    if (!chart) return;

    const tip = chart.querySelector('.chart-tip');
    const series = [['phishing', 'Phishing'], ['suspicious', 'Suspicious'], ['safe', 'Safe']];

    const show = (col) => {
        tip.replaceChildren();
        const title = document.createElement('strong');
        title.textContent = col.dataset.date;
        tip.append(title);

        for (const [key, label] of series) {
            const row = document.createElement('div');
            const name = document.createElement('span');
            const swatch = document.createElement('span');
            swatch.className = 'swatch swatch-' + key;
            name.append(swatch, ' ' + label);
            const value = document.createElement('span');
            value.textContent = col.dataset[key];
            row.append(name, value);
            tip.append(row);
        }

        tip.hidden = false;
        const left = col.offsetLeft + col.offsetWidth / 2 - tip.offsetWidth / 2;
        tip.style.left = Math.max(0, Math.min(left, chart.offsetWidth - tip.offsetWidth)) + 'px';
        tip.style.top = '-8px';
    };

    chart.querySelectorAll('.chart-col').forEach((col) => {
        col.addEventListener('mouseenter', () => show(col));
        col.addEventListener('focus', () => show(col));
        col.addEventListener('mouseleave', () => { tip.hidden = true; });
        col.addEventListener('blur', () => { tip.hidden = true; });
    });
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
