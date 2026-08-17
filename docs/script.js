// Copy code block to clipboard
function copyCode(btn) {
  const code = btn.closest('.code-block').querySelector('code').innerText;
  navigator.clipboard.writeText(code).then(() => {
    btn.textContent = 'Copied!';
    btn.style.color = '#22c55e';
    btn.style.borderColor = '#22c55e';
    setTimeout(() => {
      btn.textContent = 'Copy';
      btn.style.color = '';
      btn.style.borderColor = '';
    }, 2000);
  });
}

// Animate stat numbers on scroll
const stats = document.querySelectorAll('.stat-num');
const observer = new IntersectionObserver((entries) => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      const el = entry.target;
      const raw = el.textContent.replace(/[^0-9]/g, '');
      const suffix = el.textContent.replace(/[0-9]/g, '');
      const target = parseInt(raw);
      if (!target) return;
      let start = 0;
      const step = Math.ceil(target / 40);
      const timer = setInterval(() => {
        start = Math.min(start + step, target);
        el.textContent = start.toLocaleString() + suffix;
        if (start >= target) clearInterval(timer);
      }, 30);
      observer.unobserve(el);
    }
  });
}, { threshold: 0.5 });
stats.forEach(s => observer.observe(s));

// Smooth active nav highlight
const sections = document.querySelectorAll('section[id]');
const navLinks = document.querySelectorAll('.nav-links a[href^="#"]');
window.addEventListener('scroll', () => {
  let current = '';
  sections.forEach(s => {
    if (window.scrollY >= s.offsetTop - 80) current = s.id;
  });
  navLinks.forEach(a => {
    a.style.color = a.getAttribute('href') === '#' + current ? '#f97316' : '';
  });
}, { passive: true });
