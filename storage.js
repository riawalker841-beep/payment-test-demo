/*
 * storage.js — shared data layer for PayGate customer + admin pages.
 *
 * Uses localStorage so the customer page and admin dashboard (open in
 * different tabs/windows) can share payment records and QR configuration.
 * Falls back to an in-memory store if localStorage is unavailable (e.g.
 * some browsers block it on the file:// protocol), so the page never crashes.
 */
(function (global) {
  "use strict";

  var CONFIG_KEY = "paygate_config";
  var PAYMENTS_KEY = "paygate_payments";

  // Defaults used when no config has been saved yet.
  var DEFAULT_CONFIG = {
    merchantName: "Acme Store",
    qrImage: "" // data URL of the uploaded QR image; "" means none configured
  };

  // Pick a storage backend; fall back to memory if localStorage is blocked.
  var store = (function () {
    var mem = {};
    try {
      var t = "__pg_probe__";
      global.localStorage.setItem(t, "1");
      global.localStorage.removeItem(t);
      return {
        get: function (k) { return global.localStorage.getItem(k); },
        set: function (k, v) { global.localStorage.setItem(k, v); }
      };
    } catch (e) {
      return {
        get: function (k) { return Object.prototype.hasOwnProperty.call(mem, k) ? mem[k] : null; },
        set: function (k, v) { mem[k] = v; }
      };
    }
  })();

  function safeParse(raw, fallback) {
    try { return JSON.parse(raw); } catch (e) { return fallback; }
  }

  function getConfig() {
    var raw = store.get(CONFIG_KEY);
    if (!raw) return Object.assign({}, DEFAULT_CONFIG);
    var parsed = safeParse(raw, {});
    // Merge so newly-added fields (qrImage) get defaults even for old saves.
    return Object.assign({}, DEFAULT_CONFIG, parsed);
  }

  function setConfig(cfg) {
    store.set(CONFIG_KEY, JSON.stringify({
      merchantName: cfg.merchantName,
      qrImage: cfg.qrImage || ""
    }));
  }

  function getPayments() {
    var raw = store.get(PAYMENTS_KEY);
    if (!raw) return [];
    var parsed = safeParse(raw, []);
    return Array.isArray(parsed) ? parsed : [];
  }

  function savePayments(arr) {
    store.set(PAYMENTS_KEY, JSON.stringify(arr));
  }

  // Add a new payment record (newest first).
  function addPayment(p) {
    var list = getPayments();
    list.unshift(p);
    savePayments(list);
  }

  function findPayment(id) {
    var list = getPayments();
    for (var i = 0; i < list.length; i++) {
      if (list[i].id === id) return list[i];
    }
    return null;
  }

  function updatePaymentStatus(id, status) {
    var list = getPayments();
    var p = findPaymentIn(list, id);
    if (p) {
      p.status = status;
      p.updatedAt = new Date().toISOString();
      savePayments(list);
    }
  }

  function deletePayment(id) {
    savePayments(getPayments().filter(function (x) { return x.id !== id; }));
  }

  function clearPayments() {
    savePayments([]);
  }

  function findPaymentIn(list, id) {
    for (var i = 0; i < list.length; i++) {
      if (list[i].id === id) return list[i];
    }
    return null;
  }

  global.PayGate = {
    getConfig: getConfig,
    setConfig: setConfig,
    getPayments: getPayments,
    addPayment: addPayment,
    findPayment: findPayment,
    updatePaymentStatus: updatePaymentStatus,
    deletePayment: deletePayment,
    clearPayments: clearPayments,
    keys: { CONFIG_KEY: CONFIG_KEY, PAYMENTS_KEY: PAYMENTS_KEY }
  };
})(window);
