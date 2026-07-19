(function expose(root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  if (root) root.FirewallUi = api;
})(typeof window !== 'undefined' ? window : undefined, function buildLibrary() {
  function sumDecisionPrefix(decisions, prefix) {
    return Object.entries(decisions || {}).reduce(
      (total, [key, count]) => total + (key.startsWith(prefix) ? Number(count) || 0 : 0),
      0
    );
  }

  function percent(part, total) {
    return total > 0 ? Math.round((part / total) * 100) : 0;
  }

  function formatTime(value) {
    if (!value) return '—';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return '—';
    return new Intl.DateTimeFormat(undefined, {
      month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit'
    }).format(date);
  }

  function shortId(value, length = 12) {
    if (!value) return '—';
    return value.length > length ? `${value.slice(0, length)}…` : value;
  }

  return { sumDecisionPrefix, percent, formatTime, shortId };
});
