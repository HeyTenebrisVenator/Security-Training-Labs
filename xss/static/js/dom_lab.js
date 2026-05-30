function renderFromHash() {
  const raw = decodeURIComponent(location.hash.replace(/^#/, '')) || 'Use o hash da URL para testar.';
  document.getElementById('domOutput').innerHTML = raw;
}

document.getElementById('domButton').addEventListener('click', () => {
  const value = document.getElementById('domInput').value;
  location.hash = encodeURIComponent(value);
  renderFromHash();
});

window.addEventListener('hashchange', renderFromHash);
renderFromHash();
