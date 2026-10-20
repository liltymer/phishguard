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

    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
        value.textContent = score;
        return;
    }

    const start = performance.now();
    const tick = (now) => {
        const progress = Math.min(Math.max((now - start) / 1000, 0), 1);
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
    const clearButton = document.getElementById('clearUrl');
    const pasteButton = document.getElementById('pasteUrl');
    const scanButton = document.getElementById('scanButton');
    const overlay = document.getElementById('scanOverlay');
    let sending = false;

    form.addEventListener('submit', (event) => {
        // The overlay submits the form itself once it has finished
        event.preventDefault();
        if (sending) return;

        let value = input.value.trim();

        if (value === '') {
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
            showError('That does not look like a valid URL.');
            return;
        }

        input.value = value;
        sending = true;
        scanButton.disabled = true;
        showProgress(value, () => form.submit());
    });

    input.addEventListener('input', () => {
        error.classList.add('d-none');
        updateClear();
    });

    // "Try an example" buttons fill in a sample link and scan it
    document.querySelectorAll('[data-example]').forEach((button) => {
        button.addEventListener('click', () => {
            input.value = button.dataset.example;
            updateClear();
            form.requestSubmit();
        });
    });

    clearButton.addEventListener('click', () => {
        input.value = '';
        updateClear();
        input.focus();
    });

    // Reading the clipboard needs a secure page (https or localhost) and a supporting browser
    if (navigator.clipboard && navigator.clipboard.readText) {
        pasteButton.classList.remove('d-none');
        pasteButton.addEventListener('click', async () => {
            try {
                input.value = (await navigator.clipboard.readText()).trim();
                updateClear();
                error.classList.add('d-none');
                input.focus();
            } catch {
                showError('Your browser blocked access to the clipboard. Press Ctrl+V in the box instead.');
            }
        });
    }

    // Coming back with the browser's Back button can restore the page mid-scan
    window.addEventListener('pageshow', () => {
        sending = false;
        scanButton.disabled = false;
        overlay.hidden = true;
    });

    updateClear();

    function updateClear() {
        clearButton.classList.toggle('d-none', input.value === '');
    }

    // Step through the check names so people can see the work being done (about one second)
    function showProgress(url, done) {
        const checks = JSON.parse(overlay.dataset.checks);
        const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
        const stepTime = reduceMotion ? 20 : 65;
        const bar = document.getElementById('scanProgress');
        const count = document.getElementById('scanCount');
        const label = document.getElementById('scanCheck');

        document.getElementById('scanUrl').textContent = url;
        overlay.hidden = false;

        let i = 0;
        const step = () => {
            if (i === checks.length) {
                label.textContent = 'Done';
                done();
                return;
            }
            i++;
            count.textContent = i;
            label.textContent = checks[i - 1];
            bar.style.width = (i / checks.length * 100) + '%';
            setTimeout(step, stepTime);
        };
        step();
    }

    function showError(message) {
        error.textContent = message;
        error.classList.remove('d-none');
        input.focus();
    }
});

// Copy buttons: <button data-copy="text">, with a short "Copied" confirmation
document.addEventListener('click', async (event) => {
    const button = event.target.closest('[data-copy]');
    if (!button) return;

    const label = button.querySelector('span');
    const original = label.textContent;

    try {
        await navigator.clipboard.writeText(button.dataset.copy);
        label.textContent = 'Copied!';
    } catch {
        label.textContent = 'Copy failed';
    }
    setTimeout(() => { label.textContent = original; }, 2000);
});

// Light/dark theme switch. The saved theme is applied in <head> (includes/head.php) before the page draws.
document.addEventListener('DOMContentLoaded', () => {
    const buttons = document.querySelectorAll('[data-theme-toggle]');
    if (!buttons.length) return;

    const root = document.documentElement;

    const render = () => {
        const dark = root.getAttribute('data-bs-theme') === 'dark';
        buttons.forEach((button) => {
            button.querySelector('i').className = dark ? 'bi bi-sun-fill' : 'bi bi-moon-stars-fill';
            const label = dark ? 'Switch to light mode' : 'Switch to dark mode';
            button.setAttribute('aria-label', label);
            button.title = label;
        });
    };

    buttons.forEach((button) => button.addEventListener('click', () => {
        const next = root.getAttribute('data-bs-theme') === 'dark' ? 'light' : 'dark';
        root.setAttribute('data-bs-theme', next);
        try { localStorage.setItem('theme', next); } catch {}
        render();
    }));

    render();
});

// Home page: "Check a link" buttons jump to the scan box and focus it
document.addEventListener('click', (event) => {
    const link = event.target.closest('[data-focus-scan]');
    const input = document.getElementById('urlInput');
    if (!link || !input) return;

    event.preventDefault();
    const smooth = !window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    input.scrollIntoView({ behavior: smooth ? 'smooth' : 'auto', block: 'center' });
    input.focus({ preventScroll: true });
});

// Motion: scroll reveals, counting stats, typing placeholder, live preview and card spotlight.
// <html class="motion"> is only set when the person has not asked for reduced motion (includes/head.php).
document.addEventListener('DOMContentLoaded', () => {
    if (!document.documentElement.classList.contains('motion')) return;

    const countUp = (el) => {
        const target = Number(el.dataset.count);
        if (!target) return;
        const start = performance.now();
        const tick = (now) => {
            const progress = Math.min(Math.max((now - start) / 1100, 0), 1);
            const eased = 1 - Math.pow(1 - progress, 3);
            el.textContent = Math.round(target * eased).toLocaleString('en-US');
            if (progress < 1) requestAnimationFrame(tick);
        };
        requestAnimationFrame(tick);
    };

    const reveals = document.querySelectorAll('.reveal');
    if ('IntersectionObserver' in window) {
        const observer = new IntersectionObserver((entries) => {
            entries.forEach((entry) => {
                if (!entry.isIntersecting) return;
                entry.target.classList.add('in-view');
                entry.target.querySelectorAll('[data-count]').forEach(countUp);
                observer.unobserve(entry.target);
            });
        }, { threshold: 0.15, rootMargin: '0px 0px -40px 0px' });
        reveals.forEach((el) => observer.observe(el));
    } else {
        reveals.forEach((el) => el.classList.add('in-view'));
    }

    // Placeholder types out example links until the person clicks into the box
    const input = document.getElementById('urlInput');
    if (input && input.dataset.typing) {
        const words = JSON.parse(input.dataset.typing);
        const original = input.placeholder;
        let word = 0, chars = 0, deleting = false;

        const type = () => {
            if (document.activeElement === input || input.value !== '') {
                input.placeholder = original;
                setTimeout(type, 800);
                return;
            }
            let delay = deleting ? 30 : 70;
            chars += deleting ? -1 : 1;
            input.placeholder = 'Try: ' + words[word].slice(0, chars);
            if (!deleting && chars === words[word].length) {
                deleting = true;
                delay = 1600;
            } else if (deleting && chars === 0) {
                deleting = false;
                word = (word + 1) % words.length;
                delay = 350;
            }
            setTimeout(type, delay);
        };
        setTimeout(type, 1400);
    }

    // Live preview card: cycles through the real results for the example links
    const card = document.getElementById('previewCard');
    if (card) {
        const demos = JSON.parse(card.dataset.demos);
        const dots = document.querySelectorAll('#previewDots span');
        const gauge = card.querySelector('.mini-gauge');
        const scoreEl = card.querySelector('[data-field="score"]');
        const field = (name) => card.querySelector(`[data-field="${name}"]`);
        let current = 0;

        const reasonItem = (badgeColor, badgeText, text) => {
            const li = document.createElement('li');
            const badge = document.createElement('span');
            badge.className = 'badge text-bg-' + badgeColor;
            badge.textContent = badgeText;
            const message = document.createElement('span');
            message.textContent = text;
            li.append(badge, ' ', message);
            return li;
        };

        const show = (demo) => {
            card.classList.add('swap');
            setTimeout(() => {
                const from = Number(scoreEl.textContent);
                card.className = card.className.replace(/verdict-\w+/, 'verdict-' + demo.verdict);
                field('url').textContent = demo.url;
                field('label').textContent = demo.label;
                field('icon').className = 'bi ' + demo.icon;
                field('reasons').replaceChildren(...(demo.reasons.length
                    ? demo.reasons.map((r) => reasonItem(r.color, r.level, r.text))
                    : [reasonItem('success', 'Clear', 'No warning signs found.')]));
                gauge.style.setProperty('--score', demo.score);

                const start = performance.now();
                const tick = (now) => {
                    const progress = Math.min(Math.max((now - start) / 900, 0), 1);
                    scoreEl.textContent = Math.round(from + (demo.score - from) * (1 - Math.pow(1 - progress, 3)));
                    if (progress < 1) requestAnimationFrame(tick);
                };
                requestAnimationFrame(tick);

                dots.forEach((dot, i) => dot.classList.toggle('active', i === current));
                card.classList.remove('swap');
            }, 300);
        };

        setInterval(() => {
            if (document.hidden) return;
            current = (current + 1) % demos.length;
            show(demos[current]);
        }, 4500);
    }

    // Spotlight that follows the cursor over feature cards
    document.querySelectorAll('.feature-card').forEach((featureCard) => {
        featureCard.addEventListener('pointermove', (event) => {
            const rect = featureCard.getBoundingClientRect();
            featureCard.style.setProperty('--mx', (event.clientX - rect.left) + 'px');
            featureCard.style.setProperty('--my', (event.clientY - rect.top) + 'px');
        });
    });
});

// History: clicking anywhere on a row opens that result (the arrow link inside stays keyboard-accessible)
document.addEventListener('click', (event) => {
    const row = event.target.closest('tr[data-href]');
    if (!row || event.target.closest('a, button') || window.getSelection().toString()) return;
    window.location.href = row.dataset.href;
});

// Show or hide a password field: <button data-toggle-password="fieldId">
document.addEventListener('click', (event) => {
    const button = event.target.closest('[data-toggle-password]');
    if (!button) return;

    const field = document.getElementById(button.dataset.togglePassword);
    const show = field.type === 'password';
    field.type = show ? 'text' : 'password';
    button.querySelector('i').className = show ? 'bi bi-eye-slash' : 'bi bi-eye';
    button.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
});

// Press "/" to jump to a search box marked with data-shortcut="/"
document.addEventListener('keydown', (event) => {
    if (event.key !== '/' || event.ctrlKey || event.metaKey || event.altKey) return;
    const target = event.target;
    if (target.closest('input, textarea, select, [contenteditable="true"]')) return;
    const search = document.querySelector('[data-shortcut="/"]');
    if (!search) return;
    event.preventDefault();
    search.focus();
    search.select();
});
