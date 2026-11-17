// DevTalk site-wide behaviour, kept in a file (not inline) so the
// Content-Security-Policy can forbid inline script.

// Any link or button with data-confirm="..." asks before continuing
// (replaces the old inline onclick="return confirm(...)").
document.addEventListener('click', (event) => {
    const el = event.target.closest('[data-confirm]');
    if (el && !window.confirm(el.dataset.confirm)) {
        event.preventDefault();
    }
});
