/* Documentation search, navigation and reader tools. No third-party services. */
(() => {
  'use strict';
  const root = document.body.dataset.root || '';
  const dialog = document.querySelector('.search-dialog');
  const input = document.querySelector('#docs-search');
  const edition = document.querySelector('#search-edition');
  const results = document.querySelector('.search-results');
  const status = document.querySelector('.search-status');
  let entries;
  let loading;
  let sequence = 0;
  let returnFocus;
  try {
    const preference = localStorage.getItem('verifier-docs-theme');
    if (preference === 'dark' || preference === 'light') document.documentElement.dataset.theme = preference;
  } catch (_) { /* The site remains usable with browser storage disabled. */ }
  document.querySelector('.theme-toggle').addEventListener('click', () => {
    const theme = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
    document.documentElement.dataset.theme = theme;
    try { localStorage.setItem('verifier-docs-theme', theme); } catch (_) {}
  });
  const menu = document.querySelector('.menu-toggle');
  const sidebar = document.querySelector('.portal-sidebar');
  function closeMenu() { sidebar.classList.remove('open'); menu.setAttribute('aria-expanded', 'false'); }
  menu.addEventListener('click', () => {
    const open = sidebar.classList.toggle('open');
    menu.setAttribute('aria-expanded', String(open));
    if (open) sidebar.querySelector('summary').focus();
  });
  document.addEventListener('click', event => {
    if (!sidebar.contains(event.target) && !menu.contains(event.target)) closeMenu();
  });
  document.addEventListener('keydown', event => {
    if (event.key === 'Escape') {
      closeMenu();
      if (dialog.open) { event.preventDefault(); dialog.close(); }
    }
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
      event.preventDefault();
      openSearch();
    }
  });
  async function loadIndex() {
    if (entries) return entries;
    if (!loading) loading = fetch(root + 'search-index.json').then(response => {
      if (!response.ok) throw new Error('Search index unavailable');
      return response.json();
    }).then(data => {
      if (!Array.isArray(data)) throw new Error('Invalid search index');
      entries = data.map(entry => ({...entry, haystack: (entry.title + ' ' + entry.page + ' ' + entry.text).toLowerCase()}));
      return entries;
    }).catch(error => { loading = null; throw error; });
    return loading;
  }
  function openSearch() {
    if (!dialog.open) { returnFocus = document.activeElement; dialog.showModal(); }
    input.focus();
    search();
  }
  document.querySelector('.search-trigger').addEventListener('click', openSearch);
  dialog.addEventListener('close', () => { if (returnFocus && returnFocus.isConnected) returnFocus.focus(); });
  dialog.addEventListener('click', event => {
    const bounds = dialog.getBoundingClientRect();
    if (event.target === dialog && (event.clientX < bounds.left || event.clientX > bounds.right || event.clientY < bounds.top || event.clientY > bounds.bottom)) dialog.close();
  });
  async function search() {
    const ticket = ++sequence;
    const query = input.value.toLowerCase().trim();
    results.replaceChildren();
    if (!query) { status.textContent = 'Search guides, concepts, commands, and Python exports.'; return; }
    status.textContent = 'Searching…';
    try {
      const index = await loadIndex();
      if (ticket !== sequence) return;
      const tokens = query.split(/\s+/).filter(Boolean);
      const matches = index.filter(entry => (edition.value === 'all' || entry.edition === edition.value) && tokens.every(token => entry.haystack.includes(token))).map(entry => {
        const heading = entry.title.toLowerCase();
        const score = (heading === query ? 100 : 0) + (heading.includes(query) ? 40 : 0) + tokens.filter(token => heading.includes(token)).length * 8;
        return {entry, score};
      }).sort((a, b) => b.score - a.score || a.entry.url.localeCompare(b.entry.url));
      status.textContent = matches.length ? `${matches.length} matching sections${matches.length > 35 ? ' · showing the first 35' : ''}` : 'No matches. Try a command name, a concept, or fewer words.';
      for (const {entry} of matches.slice(0, 35)) {
        const anchor = document.createElement('a');
        anchor.className = 'search-result';
        anchor.href = root + entry.url;
        const title = document.createElement('strong'); title.textContent = entry.title;
        const meta = document.createElement('small'); meta.textContent = (entry.edition === 'release' ? 'Released package' : 'Repository source') + ' · ' + entry.page;
        const snippet = document.createElement('p');
        const at = Math.max(0, entry.text.toLowerCase().indexOf(tokens[0]) - 55);
        snippet.textContent = (at ? '…' : '') + entry.text.slice(at, at + 170) + (entry.text.length > at + 170 ? '…' : '');
        anchor.append(meta, title, snippet); results.append(anchor);
      }
    } catch (_) { if (ticket === sequence) status.textContent = 'Search could not load. Use the guide index or retry your search.'; }
  }
  input.addEventListener('input', search);
  edition.addEventListener('change', search);
  input.addEventListener('keydown', event => {
    if (event.key === 'ArrowDown') { event.preventDefault(); results.querySelector('a')?.focus(); }
    if (event.key === 'Enter') { event.preventDefault(); results.querySelector('a')?.click(); }
  });
  results.addEventListener('keydown', event => {
    if (event.key !== 'ArrowDown' && event.key !== 'ArrowUp') return;
    event.preventDefault();
    const current = document.activeElement;
    const next = event.key === 'ArrowDown' ? current.nextElementSibling : current.previousElementSibling;
    if (next) next.focus(); else input.focus();
  });
  document.querySelectorAll('.portal-content pre').forEach(block => {
    const code = block.querySelector('code');
    if (!code || !navigator.clipboard) return;
    const button = document.createElement('button'); button.className = 'code-copy'; button.type = 'button';
    button.textContent = 'Copy'; button.setAttribute('aria-label', 'Copy code');
    button.addEventListener('click', async () => {
      try { await navigator.clipboard.writeText(code.textContent); button.textContent = 'Copied'; }
      catch (_) { button.textContent = 'Select to copy'; }
      setTimeout(() => { button.textContent = 'Copy'; }, 1800);
    });
    block.append(button);
  });
  const tocLinks = [...document.querySelectorAll('.portal-toc > a')];
  if ('IntersectionObserver' in window) {
    const observer = new IntersectionObserver(changes => {
      for (const change of changes) if (change.isIntersecting) {
        for (const link of tocLinks) link.classList.toggle('active', link.hash === '#' + change.target.id);
      }
    }, {rootMargin: '-90px 0px -65% 0px'});
    for (const link of tocLinks) { const target = document.getElementById(link.hash.slice(1)); if (target) observer.observe(target); }
  }
})();
