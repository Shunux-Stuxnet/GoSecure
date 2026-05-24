/* ================================================================
   GoSecure -- script.js
   Animated bg, dual-mode, security scan report card,
   multi-select parallel checks, rich data display
   ================================================================ */

/* -- Animated background (particle network) --------------------- */
(function initBg() {
  var canvas = document.getElementById('bg-canvas');
  if (!canvas) return;
  var ctx = canvas.getContext('2d');
  var W, H, pts;
  function resize() { W = canvas.width = window.innerWidth; H = canvas.height = window.innerHeight; }
  function make() {
    pts = [];
    var n = Math.min(70, Math.floor(W * H / 16000));
    for (var i = 0; i < n; i++) {
      pts.push({ x: Math.random()*W, y: Math.random()*H,
                 vx: (Math.random()-0.5)*0.22, vy: (Math.random()-0.5)*0.22,
                 r: Math.random()*1.4+0.5 });
    }
  }
  function draw() {
    ctx.clearRect(0, 0, W, H);
    var n = pts.length;
    for (var i = 0; i < n; i++) {
      var p = pts[i];
      p.x += p.vx; p.y += p.vy;
      if (p.x < 0 || p.x > W) p.vx *= -1;
      if (p.y < 0 || p.y > H) p.vy *= -1;
    }
    for (var i = 0; i < n; i++) {
      for (var j = i+1; j < n; j++) {
        var dx = pts[i].x-pts[j].x, dy = pts[i].y-pts[j].y, d2 = dx*dx+dy*dy;
        if (d2 < 14400) {
          ctx.beginPath();
          ctx.strokeStyle = 'rgba(0,255,156,'+(0.07*(1-Math.sqrt(d2)/120))+')';
          ctx.lineWidth = 0.5;
          ctx.moveTo(pts[i].x, pts[i].y); ctx.lineTo(pts[j].x, pts[j].y);
          ctx.stroke();
        }
      }
    }
    pts.forEach(function(p) {
      ctx.beginPath(); ctx.arc(p.x, p.y, p.r, 0, Math.PI*2);
      ctx.fillStyle = 'rgba(0,255,156,0.22)'; ctx.fill();
    });
    requestAnimationFrame(draw);
  }
  resize(); make(); draw();
  window.addEventListener('resize', function() { resize(); make(); });
})();

/* -- Mode toggle ------------------------------------------------- */
document.querySelectorAll('.mode-btn').forEach(function(btn) {
  btn.addEventListener('click', function() {
    document.querySelectorAll('.mode-btn').forEach(function(b) { b.classList.remove('active'); });
    this.classList.add('active');
    document.body.classList.remove('mode-beginner', 'mode-pro');
    document.body.classList.add('mode-' + this.dataset.mode);
  });
});

/* -- Tab switching ----------------------------------------------- */
document.querySelectorAll('.tab-btn').forEach(function(btn) {
  btn.addEventListener('click', function() {
    document.querySelectorAll('.tab-btn').forEach(function(b) { b.classList.remove('active'); });
    document.querySelectorAll('.tab-content').forEach(function(c) { c.classList.remove('active'); });
    this.classList.add('active');
    document.getElementById('tab-' + this.dataset.tab).classList.add('active');
    document.getElementById('r-fullScan').checked = (this.dataset.tab === 'fullscan');
    refreshBtnLabel();
  });
});

/* -- Checkbox change listeners ----------------------------------- */
document.addEventListener('change', function(e) {
  if (e.target && e.target.type === 'checkbox' && e.target.name === 'functionality') {
    var tab = e.target.closest('.tab-content');
    if (tab) updateSelCount(tab);
    refreshBtnLabel();
  }
});

function updateSelCount(tab) {
  var total = tab.querySelectorAll('input[type="checkbox"]').length;
  var count = tab.querySelectorAll('input[type="checkbox"]:checked').length;
  var el = tab.querySelector('.sel-count');
  if (!el) return;
  el.textContent = count + ' of ' + total + ' selected';
  if (count > 0) el.classList.add('has-selection');
  else           el.classList.remove('has-selection');
}

function refreshBtnLabel() {
  var btn = document.getElementById('scanBtn');
  if (!btn) return;
  var activeTab = document.querySelector('.tab-btn.active');
  if (!activeTab) return;
  var tab = activeTab.dataset.tab;
  if (tab === 'fullscan') {
    btn.querySelector('.btn-text').innerHTML = '<i class="fas fa-bolt"></i> Security Scan';
    return;
  }
  var tabEl = document.getElementById('tab-' + tab);
  var count = tabEl ? tabEl.querySelectorAll('input[type="checkbox"]:checked').length : 0;
  if (count === 0) {
    btn.querySelector('.btn-text').innerHTML = '<i class="fas fa-bolt"></i> Scan';
  } else {
    btn.querySelector('.btn-text').innerHTML = '<i class="fas fa-bolt"></i> Run <span class="btn-count">' + count + '</span> Check' + (count > 1 ? 's' : '');
  }
}

/* -- Select All / None helpers (called from HTML) ---------------- */
function selectAll(btn) {
  var tab = btn.closest('.tab-content');
  tab.querySelectorAll('input[type="checkbox"]').forEach(function(cb) { cb.checked = true; });
  updateSelCount(tab);
  refreshBtnLabel();
}
function selectNone(btn) {
  var tab = btn.closest('.tab-content');
  tab.querySelectorAll('input[type="checkbox"]').forEach(function(cb) { cb.checked = false; });
  updateSelCount(tab);
  refreshBtnLabel();
}

/* -- Route map --------------------------------------------------- */
var ROUTES = {
  fullScan:        function(t) { return { url:'/full-scan',       fd:fd('url',t) }; },
  dnsLookup:       function(t) { return { url:'/dnsinfo',         fd:fd('hostname',t) }; },
  dnssec:          function(t) { return { url:'/dnssec',          fd:fd('url',t) }; },
  dns:             function(t) { return { url:'/resolve',         fd:fd('url',t) }; },
  whois:           function(t) { return { url:'/whois',           fd:fd('url',t) }; },
  subdomainEnum:   function(t) { return { url:'/subdomain-enum',  fd:fd('url',t) }; },
  securityHeaders: function(t) { return { url:'/security-headers',fd:fd('url',t) }; },
  cookieAudit:     function(t) { return { url:'/cookie',          fd:fd('url',t) }; },
  hstsChecker:     function(t) { return { url:'/hsts',            fd:fd('url',t) }; },
  cspAnalysis:     function(t) { return { url:'/csp-analysis',    fd:fd('url',t) }; },
  clickjacking:    function(t) { return { url:'/clickjacking',    fd:fd('url',t) }; },
  corsCheck:       function(t) { return { url:'/cors-check',      fd:fd('url',t) }; },
  redirectChain:   function(t) { return { url:'/redirect-chain',  fd:fd('url',t) }; },
  mixedContent:    function(t) { return { url:'/mixed-content',   fd:fd('url',t) }; },
  sriCheck:        function(t) { return { url:'/sri-check',       fd:fd('url',t) }; },
  openRedirect:    function(t) { return { url:'/open-redirect',   fd:fd('url',t) }; },
  getData:         function(t) { return { url:'/getData?url='+encodeURIComponent(t), fd:null }; },
  portScanner:     function(t) { return { url:'/scan',            fd:fd('hostname',t) }; },
  servstat:        function(t) { return { url:'/servs',           fd:fd('url',t) }; },
  SSLInfo:         function(t) { return { url:'/sslinfo',         fd:fd('url',t) }; },
  tlsAnalysis:     function(t) { return { url:'/tls-analysis',    fd:fd('url',t) }; },
  techDetect:      function(t) { return { url:'/tech-detect',     fd:fd('url',t) }; },
  outdatedCheck:   function(t) { return { url:'/outdated-check',  fd:fd('url',t) }; },
  jsAudit:         function(t) { return { url:'/js-audit',        fd:fd('url',t) }; },
  sitemap:         function(t) { return { url:'/sitemap',         fd:fd('url',t) }; },
  crawlcheck:      function(t) { return { url:'/crawlcheck',      fd:fdK('siteURL',t) }; },
  emailSecurity:   function(t) { return { url:'/email-security',  fd:fd('url',t) }; },
  // Phase 5: extra free checks
  httpProtocols:   function(t) { return { url:'/http-protocols',  fd:fd('url',t) }; },
  securityTxt:     function(t) { return { url:'/security-txt',    fd:fd('url',t) }; },
  socialTags:      function(t) { return { url:'/social-tags',     fd:fd('url',t) }; },
  wafDetect:       function(t) { return { url:'/waf-detect',      fd:fd('url',t) }; },
  caaRecords:      function(t) { return { url:'/caa-records',     fd:fd('url',t) }; },
  ipGeo:           function(t) { return { url:'/ip-geo',          fd:fd('url',t) }; },
  archiveHistory:  function(t) { return { url:'/archive-history', fd:fd('url',t) }; },
  carbon:          function(t) { return { url:'/carbon',          fd:fd('url',t) }; },
  httpMethods:     function(t) { return { url:'/http-methods',    fd:fd('url',t) }; },
  cipherSuites:    function(t) { return { url:'/cipher-suites',   fd:fd('url',t) }; },
  linkedPages:     function(t) { return { url:'/linked-pages',    fd:fd('url',t) }; },
  dnsBlocks:       function(t) { return { url:'/dns-blocks',      fd:fd('url',t) }; },
  // Phase 6: web-check parity additions
  siteFeatures:    function(t) { return { url:'/site-features',   fd:fd('url',t) }; },
  malwareCheck:    function(t) { return { url:'/malware-check',   fd:fd('url',t) }; },
  globalRanking:   function(t) { return { url:'/global-ranking',  fd:fd('url',t) }; },
  sslChain:        function(t) { return { url:'/ssl-chain',       fd:fd('url',t) }; },
  ctSubdomains:    function(t) { return { url:'/ct-subdomains',   fd:fd('url',t) }; },
  bimi:            function(t) { return { url:'/bimi',            fd:fd('url',t) }; },
  sslLabs:         function(t) { return { url:'/ssl-labs',        fd:fd('url',t) }; }
};

function fd(key, val)  { var f = new FormData(); f.append(key, val); return f; }
function fdK(key, val) { var f = new FormData(); f.append(key, val); return f; }

/* -- Form submit ------------------------------------------------- */
document.getElementById('functionalityForm').addEventListener('submit', function(e) {
  e.preventDefault();
  var target = document.getElementById('inputField').value.trim();
  if (!target) { document.getElementById('inputField').focus(); return; }

  var activeTab = document.querySelector('.tab-btn.active').dataset.tab;
  var btn = document.getElementById('scanBtn');
  var rc  = document.getElementById('responseContainer');

  if (activeTab === 'fullscan') {
    setBusy(btn, true);
    rc.style.display = 'block';
    rc.innerHTML = scanningHTML('fullScan', target);
    fetchOne('fullScan', target).then(function(data) {
      setBusy(btn, false);
      if (data._error) {
        rc.innerHTML = '<div class="error-card"><i class="fas fa-circle-xmark"></i> ' + esc(data._error) + '</div>';
      } else {
        rc.innerHTML = formatFullScan(data);
      }
    });
    return;
  }

  // Multi-check tabs
  var tabEl = document.getElementById('tab-' + activeTab);
  var checked = tabEl.querySelectorAll('input[type="checkbox"]:checked');
  var funcs = [];
  checked.forEach(function(cb) { funcs.push(cb.value); });

  if (!funcs.length) {
    alert('Select at least one check from the list above.');
    return;
  }

  setBusy(btn, true);
  rc.style.display = 'block';
  rc.innerHTML = multiScanningHTML(funcs, target);

  var promises = funcs.map(function(f) { return fetchOne(f, target); });

  Promise.all(promises).then(function(results) {
    setBusy(btn, false);
    rc.innerHTML = formatMultiResult(funcs, results, target);
  }).catch(function(err) {
    setBusy(btn, false);
    rc.innerHTML = '<div class="error-card"><i class="fas fa-circle-xmark"></i> ' + esc(err.message) + '</div>';
  });
});

function setBusy(btn, busy) {
  btn.disabled = busy;
  btn.querySelector('.btn-text').style.display    = busy ? 'none' : 'flex';
  btn.querySelector('.btn-loading').style.display = busy ? 'flex' : 'none';
  if (!busy) refreshBtnLabel();
}

/* -- Fetch single check ----------------------------------------- */
function fetchOne(func, target) {
  var route = ROUTES[func] && ROUTES[func](target);
  if (!route) return Promise.resolve({ _error: 'Unknown check: ' + func });
  var p = route.fd ? fetch(route.url, { method:'POST', body:route.fd }) : fetch(route.url);
  return p.then(function(r) {
    if (!r.ok) throw new Error('HTTP ' + r.status);
    return r.text();
  }).then(function(raw) {
    try { return JSON.parse(raw); } catch(_) { return { _raw: raw }; }
  }).catch(function(err) {
    return { _error: err.message };
  });
}

/* -- Scanning overlays ------------------------------------------ */
var FUNC_LABELS = {
  fullScan:'Running full security scan', dnsLookup:'Querying DNS records',
  dnssec:'Checking DNSSEC', dns:'Resolving nameservers', whois:'Looking up WHOIS data',
  subdomainEnum:'Enumerating subdomains', securityHeaders:'Analyzing security headers',
  cookieAudit:'Auditing cookie flags', hstsChecker:'Checking HSTS policy',
  cspAnalysis:'Analyzing Content Security Policy', clickjacking:'Testing clickjacking protection',
  corsCheck:'Testing CORS configuration', redirectChain:'Tracing redirect chain',
  mixedContent:'Scanning for mixed content', sriCheck:'Auditing SRI integrity',
  openRedirect:'Testing open redirect params', getData:'Fetching response headers',
  portScanner:'Scanning TCP ports', servstat:'Checking server status',
  SSLInfo:'Retrieving SSL certificate', tlsAnalysis:'Analyzing TLS/cipher config',
  techDetect:'Fingerprinting technology stack', outdatedCheck:'Checking for outdated software',
  jsAudit:'Auditing JS libraries', sitemap:'Fetching sitemap',
  crawlcheck:'Fetching robots.txt', emailSecurity:'Checking SPF / DKIM / DMARC',
  httpProtocols:'Probing HTTP/2 & HTTP/3', securityTxt:'Looking for security.txt',
  socialTags:'Parsing social meta tags', wafDetect:'Fingerprinting WAF / CDN',
  caaRecords:'Checking CAA DNS records', ipGeo:'Geolocating server IP',
  archiveHistory:'Querying Wayback Machine', carbon:'Estimating carbon footprint',
  httpMethods:'Enumerating HTTP methods', cipherSuites:'Probing TLS cipher suites',
  linkedPages:'Extracting linked pages', dnsBlocks:'Testing DNS block filters',
  siteFeatures:'Auditing modern web features', malwareCheck:'Checking threat intel feeds',
  globalRanking:'Looking up Tranco global rank', sslChain:'Walking full SSL cert chain',
  ctSubdomains:'Mining Certificate Transparency logs', bimi:'Checking BIMI brand record',
  sslLabs:'Running SSL Labs deep audit (slow)'
};

var FUNC_ICONS = {
  fullScan:'fa-shield-virus', dnsLookup:'fa-map-pin', dnssec:'fa-key',
  dns:'fa-server', whois:'fa-id-card', subdomainEnum:'fa-sitemap',
  securityHeaders:'fa-shield-halved', cookieAudit:'fa-cookie-bite',
  hstsChecker:'fa-lock', cspAnalysis:'fa-file-shield', clickjacking:'fa-display',
  corsCheck:'fa-right-left', redirectChain:'fa-route', mixedContent:'fa-circle-half-stroke',
  sriCheck:'fa-fingerprint', openRedirect:'fa-arrow-up-right-from-square',
  getData:'fa-code', portScanner:'fa-network-wired', servstat:'fa-heart-pulse',
  SSLInfo:'fa-certificate', tlsAnalysis:'fa-lock-open', techDetect:'fa-magnifying-glass-chart',
  outdatedCheck:'fa-triangle-exclamation', jsAudit:'fa-js',
  sitemap:'fa-map', crawlcheck:'fa-robot', emailSecurity:'fa-envelope-circle-check',
  httpProtocols:'fa-bolt-lightning', securityTxt:'fa-file-lines',
  socialTags:'fa-share-nodes', wafDetect:'fa-shield',
  caaRecords:'fa-stamp', ipGeo:'fa-globe',
  archiveHistory:'fa-clock-rotate-left', carbon:'fa-leaf',
  httpMethods:'fa-code-branch', cipherSuites:'fa-shuffle',
  linkedPages:'fa-link', dnsBlocks:'fa-ban'
};

function scanningHTML(func, target) {
  return '<div class="scanning-status">' +
    '<div class="spinner-ring"></div>' +
    '<div class="scan-target">' + esc(target) + '</div>' +
    '<div class="scan-msg">' + (FUNC_LABELS[func] || 'Scanning') + '<span class="scan-dots"></span></div>' +
    '</div>';
}

function multiScanningHTML(funcs, target) {
  var names = funcs.map(function(f) { return FUNC_LABELS[f] || f; }).join(', ');
  return '<div class="scanning-status">' +
    '<div class="spinner-ring"></div>' +
    '<div class="scan-target">' + esc(target) + '</div>' +
    '<div class="scan-msg">Running ' + funcs.length + ' check' + (funcs.length>1?'s':'') + ' in parallel<span class="scan-dots"></span></div>' +
    '<div style="font-size:11px;color:var(--text-dim);margin-top:6px;font-family:var(--font-mono)">' + esc(names) + '</div>' +
    '</div>';
}

/* -- Multi-result renderer -------------------------------------- */
function formatMultiResult(funcs, results, target) {
  var html =
    '<div class="multi-results">' +
    '<div class="multi-results-header">' +
      '<div class="multi-results-title"><i class="fas fa-list-check"></i> Results for ' + esc(target) + '</div>' +
      '<div class="multi-results-meta">' + funcs.length + ' check' + (funcs.length>1?'s':'') + ' &middot; ' + new Date().toLocaleTimeString() + '</div>' +
    '</div>';

  funcs.forEach(function(func, i) {
    var data = results[i];
    var lbl  = FUNC_LABELS[func] || func;
    var ico  = FUNC_ICONS[func]  || 'fa-circle-dot';
    var isErr = data && (data._error || data._raw);

    html +=
      '<div class="multi-result-card' + (isErr ? ' card-error' : '') + '">' +
        '<div class="multi-result-header">' +
          '<div class="header-icon' + (isErr ? ' icon-error' : '') + '"><i class="fas ' + ico + '"></i></div>' +
          lbl +
        '</div>' +
        '<div class="multi-result-body">';

    if (data && data._error) {
      html += '<div class="error-inline"><i class="fas fa-circle-xmark"></i> ' + esc(data._error) + '</div>';
    } else if (data && data._raw) {
      html += '<pre style="color:var(--text-muted);font-size:12px;white-space:pre-wrap;overflow:auto">' + esc(data._raw) + '</pre>';
    } else {
      html += renderObj(data, 0);
      html += '<button class="raw-toggle" onclick="toggleRaw(this)"><i class="fas fa-code"></i> Raw JSON</button>';
      html += '<div class="raw-json">' + esc(JSON.stringify(data, null, 2)) + '</div>';
    }

    html += '</div></div>';
  });

  html += '</div>';
  return html;
}

/* -- Full security scan report card ----------------------------- */
var CLABELS = {
  // Scored checks
  securityHeaders:'Security Headers', tls:'TLS / Cipher', csp:'CSP Policy',
  hsts:'HSTS', clickjacking:'Clickjacking', cors:'CORS Config',
  cookies:'Cookie Security', openRedirect:'Open Redirect',
  mixedContent:'Mixed Content', sri:'SRI Integrity',
  outdatedSoftware:'Outdated Software', emailSecurity:'Email Security',
  redirectChain:'Redirect Chain', jsLibraries:'JS Libraries',
  // DNS informational
  whois:'WHOIS Lookup', dnsLookup:'DNS Records', dnssec:'DNSSEC',
  serverInfo:'DNS Server Info', subdomainEnum:'Subdomain Enumeration',
  // Tech Stack informational
  remoteHeaders:'Response Headers', portScan:'Open Ports',
  serverStatus:'Server Status', sslInfo:'SSL Certificate',
  techDetect:'Technology Stack', sitemap:'Sitemap', crawlRules:'Robots.txt',
  // Phase 5 informational
  httpProtocols:'HTTP/2 & HTTP/3', securityTxt:'security.txt',
  socialTags:'Social Meta Tags', wafDetect:'WAF / CDN',
  caaRecords:'CAA Records', ipGeo:'IP Geolocation',
  archiveHistory:'Archive History', carbon:'Carbon Footprint',
  httpMethods:'HTTP Methods', cipherSuites:'Cipher Suites',
  linkedPages:'Linked Pages', dnsBlocks:'DNS Block Filters',
  // Phase 6 informational
  siteFeatures:'Site Features', malwareCheck:'Malware & Phishing',
  globalRanking:'Global Ranking', sslChain:'SSL Certificate Chain',
  ctSubdomains:'CT Log Subdomains', bimi:'BIMI Record',
  sslLabs:'SSL Labs Audit'
};

var CICONS = {
  // Scored checks
  securityHeaders:'fa-shield-halved', tls:'fa-lock', csp:'fa-file-shield',
  hsts:'fa-lock', clickjacking:'fa-display', cors:'fa-right-left',
  cookies:'fa-cookie-bite', openRedirect:'fa-arrow-up-right-from-square',
  mixedContent:'fa-circle-half-stroke', sri:'fa-fingerprint',
  outdatedSoftware:'fa-triangle-exclamation', emailSecurity:'fa-envelope-circle-check',
  redirectChain:'fa-route', jsLibraries:'fa-js',
  // DNS informational
  whois:'fa-id-card', dnsLookup:'fa-map-pin', dnssec:'fa-key',
  serverInfo:'fa-server', subdomainEnum:'fa-sitemap',
  // Tech Stack informational
  remoteHeaders:'fa-code', portScan:'fa-network-wired',
  serverStatus:'fa-heart-pulse', sslInfo:'fa-certificate',
  techDetect:'fa-magnifying-glass-chart', sitemap:'fa-map', crawlRules:'fa-robot',
  // Phase 5 informational
  httpProtocols:'fa-bolt-lightning', securityTxt:'fa-file-lines',
  socialTags:'fa-share-nodes', wafDetect:'fa-shield',
  caaRecords:'fa-stamp', ipGeo:'fa-globe',
  archiveHistory:'fa-clock-rotate-left', carbon:'fa-leaf',
  httpMethods:'fa-code-branch', cipherSuites:'fa-shuffle',
  linkedPages:'fa-link', dnsBlocks:'fa-ban',
  // Phase 6 informational
  siteFeatures:'fa-mobile-screen-button', malwareCheck:'fa-bug',
  globalRanking:'fa-ranking-star', sslChain:'fa-link-slash',
  ctSubdomains:'fa-magnifying-glass', bimi:'fa-envelope-open-text',
  sslLabs:'fa-flask'
};

var STATUS_ICONS = { pass:'fa-circle-check', warn:'fa-circle-exclamation', fail:'fa-circle-xmark', error:'fa-circle-question' };

var BMSG = {
  securityHeaders:{ pass:'Browser security features properly configured', warn:'Some browser security features missing', fail:'Critical security headers are absent' },
  tls:            { pass:'Strong modern encryption in use', warn:'Encryption could be stronger', fail:'Weak or outdated encryption detected' },
  csp:            { pass:'Script injection attacks are blocked', warn:'Content security policy has gaps', fail:'Site is vulnerable to script injection' },
  hsts:           { pass:'HTTPS enforced on all connections', warn:'HTTPS enforcement has minor gaps', fail:'HTTP connections not forced to HTTPS' },
  clickjacking:   { pass:'Site cannot be embedded in iframes', warn:'Partial clickjacking protection', fail:'Site can be embedded to trick users' },
  cors:           { pass:'Cross-origin requests properly restricted', warn:'CORS policy may be too permissive', fail:'Other sites can impersonate your users' },
  cookies:        { pass:'Session cookies are securely configured', warn:'Some cookies missing security flags', fail:'Cookies could be stolen by attackers' },
  openRedirect:   { pass:'No open redirect vulnerabilities found', warn:'Some redirect params may be exploitable', fail:'Users can be redirected to malicious sites' },
  mixedContent:   { pass:'All page resources loaded securely', warn:'Some insecure resources on page', fail:'Insecure content loaded on HTTPS page' },
  sri:            { pass:'External scripts verified against tampering', warn:'Some scripts lack integrity checks', fail:'External scripts could be tampered with' },
  outdatedSoftware:{ pass:'No vulnerable software detected', warn:'Some software versions need updating', fail:'Vulnerable software versions detected' },
  emailSecurity:  { pass:'Email spoofing blocked by DNS records', warn:'Email security policies could be stricter', fail:'Attackers may spoof emails from this domain' },
  redirectChain:  { pass:'Redirect chain is clean and secure', warn:'Redirect chain has potential issues', fail:'Redirects include HTTP downgrade or loops' },
  jsLibraries:    { pass:'No vulnerable JS libraries found', warn:'Some libraries may have known CVEs', fail:'Vulnerable JavaScript libraries detected' }
};

var GCOL = { A:'#00FF9C', B:'#7BFF7B', C:'#FFD60A', D:'#FF9500', F:'#FF3B5C' };

function formatFullScan(data) {
  var grade = data.overallGrade || '?';
  var score = data.overallScore || 0;
  var gc    = GCOL[grade] || '#ccc';
  var s     = data.summary || {};
  var deg   = Math.round(score * 3.6) + 'deg';
  var isPro = document.body.classList.contains('mode-pro');

  var top =
    '<div class="report-card">' +
    '<div class="report-top">' +
      '<div class="gauge-wrap"><div class="gauge-ring" style="--grade-color:' + gc + ';--score-deg:' + deg + '">' +
        '<div class="gauge-inner">' +
          '<span class="gauge-grade" style="color:' + gc + '">' + grade + '</span>' +
          '<span class="gauge-score">' + score + '/100</span>' +
        '</div></div></div>' +
      '<div class="report-meta">' +
        '<div class="report-domain">' + esc(data.domain || '') + '</div>' +
        '<div class="report-subtitle">Scanned in ' + (data.scanDuration||0) + 's &nbsp;&mdash;&nbsp; ' + new Date().toLocaleTimeString() + '</div>' +
        '<div class="report-summary">' +
          '<div class="summary-stat"><span class="summary-num s-pass">' + (s.pass||0) + '</span><span class="summary-lbl">Passed</span></div>' +
          '<div class="summary-stat"><span class="summary-num s-warn">' + (s.warn||0) + '</span><span class="summary-lbl">Warnings</span></div>' +
          '<div class="summary-stat"><span class="summary-num s-fail">' + (s.fail||0) + '</span><span class="summary-lbl">Failed</span></div>' +
        '</div>' +
      '</div>' +
    '</div>';

  var grid = '<div class="report-checks-section"><div class="report-checks-title">Check Details &mdash; click any row to expand</div><div class="report-checks-grid">';

  Object.keys(data.checks || {}).forEach(function(key) {
    var c     = data.checks[key];
    var st    = c.status || 'error';
    var lbl   = CLABELS[key] || key;
    var ico   = CICONS[key]  || 'fa-circle-dot';
    var stIco = STATUS_ICONS[st] || 'fa-circle-question';
    var pts   = (c.score !== undefined) ? c.score + '/' + c.maxScore : '';
    var msgs  = BMSG[key] || {};
    var msg   = isPro ? (pts ? pts + ' pts' : st) : (msgs[st] || st);
    var detail= JSON.stringify(c.data || {}, null, 2);

    grid +=
      '<div class="check-result-wrap">' +
        '<div class="check-result-card" onclick="gstoggle(this)">' +
          '<div class="crc-icon st-' + st + '"><i class="fas ' + stIco + '"></i></div>' +
          '<div class="crc-body">' +
            '<span class="crc-label"><i class="fas ' + ico + '" style="margin-right:5px;opacity:0.4;font-size:10px"></i>' + lbl + '</span>' +
            '<span class="crc-msg">' + esc(msg) + '</span>' +
          '</div>' +
          '<span class="crc-score">' + pts + '</span>' +
        '</div>' +
        '<div class="check-detail-panel"><div class="check-detail-inner">' + esc(detail) + '</div></div>' +
      '</div>';
  });

  grid += '</div></div></div>';
  return top + grid;
}

function gstoggle(card) {
  var panel = card.nextElementSibling;
  if (panel) panel.classList.toggle('open');
}

/* -- Generic result formatter ----------------------------------- */
function formatResult(func, data) {
  return '<div class="data-display">' +
    '<div class="data-title"><i class="fas fa-terminal" style="margin-right:6px;opacity:0.5"></i>' + (FUNC_LABELS[func] || func) + '</div>' +
    renderObj(data, 0) +
    '<button class="raw-toggle" onclick="toggleRaw(this)"><i class="fas fa-code"></i> Raw JSON</button>' +
    '<div class="raw-json">' + esc(JSON.stringify(data, null, 2)) + '</div>' +
    '</div>';
}

function renderObj(data, depth) {
  if (data === null || data === undefined) return '<span style="color:var(--text-muted)">null</span>';
  if (typeof data === 'boolean') return '<span style="color:' + (data ? 'var(--green)' : 'var(--red)') + '">' + data + '</span>';
  if (typeof data === 'number')  return '<span style="color:var(--blue)">' + data + '</span>';
  if (typeof data === 'string')  return '<span style="color:var(--green)">' + esc(data) + '</span>';
  if (Array.isArray(data)) {
    if (!data.length) return '<span style="color:var(--text-muted)">[ ]</span>';
    var pad = depth > 0 ? 'padding-left:14px;border-left:2px solid var(--border)' : '';
    var h = '<div style="' + pad + '">';
    data.forEach(function(item, i) {
      h += '<div style="margin:3px 0"><span style="color:var(--text-muted);font-size:11px">[' + i + ']</span> ' + renderObj(item, depth+1) + '</div>';
    });
    return h + '</div>';
  }
  if (typeof data === 'object') {
    var keys = Object.keys(data);
    if (!keys.length) return '<span style="color:var(--text-muted)">{ }</span>';
    var pad = depth > 0 ? 'padding-left:14px;border-left:2px solid var(--border)' : '';
    var h = '<div style="' + pad + '">';
    keys.forEach(function(k) {
      h += '<div class="data-kv"><span class="data-key">' + esc(k) + '</span><span class="data-val">' + renderObj(data[k], depth+1) + '</span></div>';
    });
    return h + '</div>';
  }
  return esc(String(data));
}

function toggleRaw(btn) {
  var raw = btn.nextElementSibling;
  raw.classList.toggle('visible');
  btn.innerHTML = raw.classList.contains('visible')
    ? '<i class="fas fa-eye-slash"></i> Hide JSON'
    : '<i class="fas fa-code"></i> Raw JSON';
}

/* -- Utility ---------------------------------------------------- */
function esc(s) {
  if (typeof s !== 'string') return s;
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
