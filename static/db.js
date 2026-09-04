/* ================================================================
   GoSecure -- db.js
   Client-side persistence via IndexedDB (no external deps).
   - results store: per (domain|check) cache with TTL for fast refresh
   - scans store:   full scan-run history for the history / diff views
   Exposes window.GSDB
   ================================================================ */
(function () {
  var DB_NAME = 'gosecure';
  var DB_VERSION = 1;
  var STORE_RESULTS = 'results';
  var STORE_SCANS = 'scans';
  var _dbPromise = null;

  function openDB() {
    if (_dbPromise) return _dbPromise;
    _dbPromise = new Promise(function (resolve, reject) {
      if (!('indexedDB' in window)) { reject(new Error('IndexedDB unavailable')); return; }
      var req = indexedDB.open(DB_NAME, DB_VERSION);
      req.onupgradeneeded = function (e) {
        var db = e.target.result;
        if (!db.objectStoreNames.contains(STORE_RESULTS)) {
          db.createObjectStore(STORE_RESULTS, { keyPath: 'key' });
        }
        if (!db.objectStoreNames.contains(STORE_SCANS)) {
          var s = db.createObjectStore(STORE_SCANS, { keyPath: 'id', autoIncrement: true });
          s.createIndex('domain', 'domain', { unique: false });
          s.createIndex('ts', 'ts', { unique: false });
        }
      };
      req.onsuccess = function (e) { resolve(e.target.result); };
      req.onerror = function () { reject(req.error); };
    });
    return _dbPromise;
  }

  function tx(store, mode) {
    return openDB().then(function (db) {
      return db.transaction(store, mode).objectStore(store);
    });
  }

  function reqToPromise(request) {
    return new Promise(function (resolve, reject) {
      request.onsuccess = function () { resolve(request.result); };
      request.onerror = function () { reject(request.error); };
    });
  }

  function keyFor(domain, check) {
    return String(domain).toLowerCase() + '|' + check;
  }

  /* -- Per-check result cache ----------------------------------- */
  function cacheGet(domain, check) {
    return tx(STORE_RESULTS, 'readonly')
      .then(function (os) { return reqToPromise(os.get(keyFor(domain, check))); })
      .then(function (row) {
        if (!row) return null;
        if (row.ttl && (Date.now() - row.ts) > row.ttl) return null; // expired
        return row;
      })
      .catch(function () { return null; });
  }

  function cacheSet(domain, check, result, ttl) {
    return tx(STORE_RESULTS, 'readwrite')
      .then(function (os) {
        return reqToPromise(os.put({
          key: keyFor(domain, check),
          domain: String(domain).toLowerCase(),
          check: check,
          result: result,
          ts: Date.now(),
          ttl: ttl || 0
        }));
      })
      .catch(function () { return null; });
  }

  function cacheClear() {
    return tx(STORE_RESULTS, 'readwrite')
      .then(function (os) { return reqToPromise(os.clear()); })
      .catch(function () { return null; });
  }

  /* -- Scan-run history ----------------------------------------- */
  function saveScan(domain, checks, payload) {
    return tx(STORE_SCANS, 'readwrite')
      .then(function (os) {
        return reqToPromise(os.add({
          domain: String(domain).toLowerCase(),
          checks: checks,
          payload: payload,
          ts: Date.now()
        }));
      })
      .catch(function () { return null; });
  }

  function getScans(limit) {
    return tx(STORE_SCANS, 'readonly')
      .then(function (os) { return reqToPromise(os.getAll()); })
      .then(function (rows) {
        rows = rows || [];
        rows.sort(function (a, b) { return b.ts - a.ts; });
        return limit ? rows.slice(0, limit) : rows;
      })
      .catch(function () { return []; });
  }

  function getScan(id) {
    return tx(STORE_SCANS, 'readonly')
      .then(function (os) { return reqToPromise(os.get(Number(id))); })
      .catch(function () { return null; });
  }

  function deleteScan(id) {
    return tx(STORE_SCANS, 'readwrite')
      .then(function (os) { return reqToPromise(os.delete(Number(id))); })
      .catch(function () { return null; });
  }

  function clearScans() {
    return tx(STORE_SCANS, 'readwrite')
      .then(function (os) { return reqToPromise(os.clear()); })
      .catch(function () { return null; });
  }

  window.GSDB = {
    cacheGet: cacheGet,
    cacheSet: cacheSet,
    cacheClear: cacheClear,
    saveScan: saveScan,
    getScans: getScans,
    getScan: getScan,
    deleteScan: deleteScan,
    clearScans: clearScans
  };
})();
