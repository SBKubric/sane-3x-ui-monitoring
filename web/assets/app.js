/* mon-server admin UI — shared runtime (spec §9.1).
 *
 * One Vue application per page, no router and no bundler: this file holds
 * what every page needs — the /admin/api/* fetch wrapper with its CSRF
 * header, the theme (ConfigProvider, colorPrimary #008771, dark kept in
 * localStorage), the shell mixin behind layout.html, and the handful of
 * formatters the tables use. English only in v1; every page keeps its own
 * strings in one `strings` object.
 */
window.mon = (function () {
  'use strict';

  var THEME_KEY = 'monTheme';
  var PRIMARY = '#008771';

  /* api calls one /admin/api/* handle and always resolves to the envelope
   * {success, msg, obj} plus the HTTP status, so a caller never has to deal
   * with fetch rejections or with a body that is not JSON. The
   * X-Requested-With header is the CSRF guard every mutating handle
   * requires (spec §9.1). A 401 means the session is gone: the page walks
   * back to the login form rather than showing empty tables. */
  async function api(method, path, body) {
    var res;
    try {
      res = await fetch(path, {
        method: method,
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
        body: body === undefined ? undefined : JSON.stringify(body)
      });
    } catch (e) {
      return { success: false, msg: 'mon-server is not answering.', obj: null, status: 0 };
    }
    var env = { success: false, msg: 'Unexpected answer from mon-server.', obj: null };
    try { env = await res.json(); } catch (e) { /* keep the fallback */ }
    env.status = res.status;
    if (res.status === 401 && path.indexOf('/admin/api/') === 0) {
      location.href = '/admin/login?next=' + encodeURIComponent(location.pathname);
    }
    return env;
  }

  function storedDark() {
    try { return localStorage.getItem(THEME_KEY) === 'dark'; } catch (e) { return false; }
  }
  function storeDark(dark) {
    try { localStorage.setItem(THEME_KEY, dark ? 'dark' : 'light'); } catch (e) { /* private mode */ }
  }
  function applyDark(dark) {
    document.documentElement.setAttribute('data-theme', dark ? 'dark' : 'light');
  }

  /* themeConfig is what every page hands <a-config-provider>: the panel's
   * primary green, plus antd's dark algorithm when the toggle says so. */
  function themeConfig(dark) {
    return {
      algorithm: dark ? antd.theme.darkAlgorithm : antd.theme.defaultAlgorithm,
      token: { colorPrimary: PRIMARY, borderRadius: 6 }
    };
  }

  /* ago renders "8s ago" / "14m ago" / "3d ago" against mon-server's own
   * clock (every list handle returns `now`), so the page never disagrees
   * with the server about how old something is. */
  function ago(ts, now) {
    if (ts === null || ts === undefined || ts === 0) { return 'never'; }
    var s = Math.round((now - ts) / 1000);
    if (s < 60) { return Math.max(s, 0) + 's ago'; }
    var m = Math.round(s / 60);
    if (m < 60) { return m + 'm ago'; }
    var h = Math.round(m / 60);
    if (h < 48) { return h + 'h ago'; }
    return Math.round(h / 24) + 'd ago';
  }

  /* mmss is the pairing-code countdown of spec §9.2 ("expires mm:ss"). */
  function mmss(ms) {
    var s = Math.max(0, Math.round(ms / 1000));
    return Math.floor(s / 60) + ':' + String(s % 60).padStart(2, '0');
  }

  /* dur renders a future-or-past span as "62h" / "3d", for the certificate
   * line on the TLS tab. */
  function dur(ms) {
    var m = Math.round(Math.abs(ms) / 60000);
    if (m < 60) { return m + 'm'; }
    var h = Math.floor(m / 60);
    if (h < 48) { return h + 'h'; }
    return Math.round(h / 24) + 'd';
  }

  /* slug mirrors the server's own id derivation (registry.slugify) so the
   * Approve modal can show the permanent id under the name field before
   * anything is created. The server remains the authority: it is what
   * resolves a collision. */
  function slug(name) {
    return String(name || '').toLowerCase().replace(/[^a-z0-9_.-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 64);
  }

  /* The paths picker of the Approve and Edit modals (spec §9.2, §9.3)
   * edits a paths vocabulary (spec §5.1) as {direct, edges, hops, named}:
   * the three checkboxes, and — only while hops is unchecked — the hops
   * chosen by name. picker turns a stored list into that state (none stored
   * is the default, edges — decision #100), pickedPaths back into the list
   * the API takes (hops covers every named hop, so they are dropped with
   * it), and hopOptions lists what can be named: the probed hops of the
   * last GET /state plus any stored name the chain no longer probes, so an
   * Edit never drops one the administrator did not touch. */
  function picker(paths) {
    paths = paths || ['edges'];
    return {
      direct: paths.indexOf('direct') >= 0,
      edges: paths.indexOf('edges') >= 0,
      hops: paths.indexOf('hops') >= 0,
      named: paths.filter(function (p) { return p !== 'direct' && p !== 'edges' && p !== 'hops'; })
    };
  }
  function pickedPaths(p) {
    var out = [];
    if (p.direct) { out.push('direct'); }
    if (p.edges) { out.push('edges'); }
    if (p.hops) { out.push('hops'); } else { out = out.concat(p.named); }
    return out;
  }
  function hopOptions(chain, named) {
    var hops = (chain && chain.hops) || [];
    var out = hops.map(function (h) {
      return { value: h.path, label: h.path + (h.active ? ' (active)' : ''), probed: true };
    });
    (named || []).forEach(function (p) {
      if (!hops.some(function (h) { return h.path === p; })) {
        out.push({ value: p, label: p + ' (not probed now)', probed: false });
      }
    });
    return out;
  }

  function shortRev(rev) { return rev ? String(rev).slice(0, 8) : '—'; }
  function spaced(code) { return code ? String(code).slice(0, 3) + ' ' + String(code).slice(3) : ''; }

  /* shell is the mixin behind layout.html: the sidebar's active item, the
   * pending badge, the theme toggle and Log out. Every page mixes it in, so
   * the shell behaves identically on all three. */
  var shell = {
    data: function () {
      var el = document.getElementById('app');
      return {
        dark: storedDark(),
        page: el ? el.dataset.page : '',
        pending: el ? Number(el.dataset.pending || 0) : 0,
        now: Date.now()
      };
    },
    methods: {
      themeConfig: themeConfig,
      navClass: function (name) { return this.page === name ? 'active' : ''; },
      toggleTheme: function () { this.dark = !this.dark; storeDark(this.dark); applyDark(this.dark); },
      ago: ago,
      mmss: mmss,
      dur: dur,
      slug: slug,
      shortRev: shortRev,
      spaced: spaced,
      logout: async function () {
        await api('POST', '/admin/logout');
        location.href = '/admin/login';
      }
    }
  };

  /* start builds the page's one Vue application: antd installed, Vue's own
   * {{ }} delimiters moved out of html/template's way to [[ ]], and the
   * shell mixed in. */
  function start(options) {
    applyDark(storedDark());
    options.mixins = [shell].concat(options.mixins || []);
    var app = Vue.createApp(options);
    app.config.compilerOptions.delimiters = ['[[', ']]'];
    app.use(antd);
    app.mount('#app');
    return app;
  }

  return {
    api: api, start: start, shell: shell, themeConfig: themeConfig,
    ago: ago, mmss: mmss, dur: dur, slug: slug, shortRev: shortRev, spaced: spaced,
    picker: picker, pickedPaths: pickedPaths, hopOptions: hopOptions,
    notifyOk: function (msg) { if (msg) { antd.message.success(msg); } },
    notifyErr: function (msg) { antd.message.error(msg || 'Something went wrong.'); }
  };
})();
