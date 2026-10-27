#!/usr/bin/env node
/**
 * fonepay_verify.js
 *
 * Headless-browser last-mile payment verifier for PayGate.
 * Called by webhook.php via shell_exec / proc_open.
 *
 * Usage:
 *   node fonepay_verify.js <username> <password> <mobile> <amount>
 *
 * Exits 0 and prints JSON to stdout.
 * Exits 1 on fatal errors (prints JSON with "error" key).
 *
 * Requires:  Node.js 16+  +  `npm install puppeteer` in this directory.
 * Falls back: if puppeteer is not installed, exits 2 (PHP treats as "not available").
 */

"use strict";

const [,, username, password, mobile, amount] = process.argv;

if (!username || !password || !mobile) {
  process.stdout.write(JSON.stringify({ found: false, error: "Missing arguments: username password mobile [amount]" }));
  process.exit(1);
}

// Normalise mobile — strip country code prefix if present
const mobileDigits = mobile.replace(/\D/g, "").replace(/^977/, "").slice(-10);
const amountFloat  = parseFloat(amount) || 0;

// ── Try loading puppeteer ────────────────────────────────────────────────────
let puppeteer;
try {
  puppeteer = require("puppeteer");
} catch (e) {
  try {
    // Some installations use puppeteer-core
    puppeteer = require("puppeteer-core");
  } catch (e2) {
    process.stdout.write(JSON.stringify({ found: false, error: "puppeteer_not_installed" }));
    process.exit(2);
  }
}

// ── Main ─────────────────────────────────────────────────────────────────────
(async () => {
  let browser;
  try {
    browser = await puppeteer.launch({
      headless: "new",
      args: [
        "--no-sandbox",
        "--disable-setuid-sandbox",
        "--disable-dev-shm-usage",
        "--disable-gpu",
      ],
    });

    const page = await browser.newPage();

    // Intercept network — capture the API responses from the transactions page
    let transactions = null;
    let authToken    = null;

    page.on("response", async (response) => {
      const url = response.url();

      // Capture auth token from login response
      if (url.includes("/login") || url.includes("/auth") || url.includes("/token")) {
        try {
          const ct = response.headers()["content-type"] || "";
          if (ct.includes("json")) {
            const body = await response.json().catch(() => null);
            if (body) {
              // Common JWT field names
              authToken = body.access_token || body.accessToken || body.token
                       || body.jwt         || body.data?.token || body.data?.accessToken
                       || authToken;
            }
          }
        } catch (_) {}
      }

      // Capture transactions API response
      if (
        url.includes("transaction") ||
        url.includes("collection") ||
        url.includes("payment")
      ) {
        try {
          const ct = response.headers()["content-type"] || "";
          if (ct.includes("json")) {
            const body = await response.json().catch(() => null);
            if (body) {
              // Normalise to array
              const list =
                (Array.isArray(body) && body) ||
                (Array.isArray(body.data) && body.data) ||
                (Array.isArray(body.transactions) && body.transactions) ||
                (Array.isArray(body.collections) && body.collections) ||
                (Array.isArray(body.records) && body.records) ||
                null;
              if (list && list.length > 0) {
                transactions = transactions ? [...transactions, ...list] : list;
              }
            }
          }
        } catch (_) {}
      }
    });

    // ── Step 1: Navigate to the login page ────────────────────────────────────
    await page.goto("https://fonebiz.fonepay.com/#/login", {
      waitUntil: "networkidle2",
      timeout: 30000,
    });

    // ── Step 2: Fill in credentials ───────────────────────────────────────────
    // Try common selectors for username field
    const userSelectors = [
      'input[name="username"]',
      'input[placeholder*="username" i]',
      'input[placeholder*="mobile" i]',
      'input[placeholder*="phone" i]',
      'input[type="text"]',
      'input[type="email"]',
    ];
    const passSelectors = [
      'input[name="password"]',
      'input[type="password"]',
      'input[placeholder*="password" i]',
    ];

    let userField = null;
    for (const sel of userSelectors) {
      userField = await page.$(sel);
      if (userField) break;
    }
    if (!userField) throw new Error("Could not find username input on login page");

    let passField = null;
    for (const sel of passSelectors) {
      passField = await page.$(sel);
      if (passField) break;
    }
    if (!passField) throw new Error("Could not find password input on login page");

    await userField.click({ clickCount: 3 });
    await userField.type(username, { delay: 50 });
    await passField.click({ clickCount: 3 });
    await passField.type(password, { delay: 50 });

    // ── Step 3: Submit ────────────────────────────────────────────────────────
    const submitSelectors = [
      'button[type="submit"]',
      'input[type="submit"]',
      'button:not([type="button"])',
    ];
    let submitBtn = null;
    for (const sel of submitSelectors) {
      submitBtn = await page.$(sel);
      if (submitBtn) break;
    }

    if (submitBtn) {
      await Promise.all([
        page.waitForNavigation({ waitUntil: "networkidle2", timeout: 15000 }).catch(() => {}),
        submitBtn.click(),
      ]);
    } else {
      await page.keyboard.press("Enter");
      await page.waitForNavigation({ waitUntil: "networkidle2", timeout: 15000 }).catch(() => {});
    }

    // Check for login error
    const pageContent = await page.content();
    if (
      pageContent.includes("Invalid credentials") ||
      pageContent.includes("incorrect password") ||
      pageContent.includes("Login failed") ||
      pageContent.includes("Invalid username")
    ) {
      throw new Error("Login failed — invalid FonePay credentials");
    }

    // ── Step 4: Navigate to transactions page ─────────────────────────────────
    await page.goto("https://fonebiz.fonepay.com/#/merchant-collections/transactions", {
      waitUntil: "networkidle2",
      timeout: 30000,
    });

    // Wait a bit for the SPA to load transactions
    await new Promise(r => setTimeout(r, 3000));

    // ── Step 5: Try to read from intercepted API data first ───────────────────
    let result = matchTransaction(transactions, mobileDigits, amountFloat);

    if (!result.found) {
      // ── Fallback: scrape the rendered DOM ────────────────────────────────────
      const domTransactions = await page.evaluate(() => {
        const rows = [];
        // Try table rows
        document.querySelectorAll("table tbody tr, [class*='transaction'], [class*='collection'], [class*='payment-row']")
          .forEach(row => {
            rows.push(row.innerText || row.textContent || "");
          });
        return rows;
      });

      result = matchFromDomText(domTransactions, mobileDigits, amountFloat);
    }

    await browser.close();
    process.stdout.write(JSON.stringify(result));
    process.exit(0);

  } catch (err) {
    if (browser) await browser.close().catch(() => {});
    const errMsg = err && err.message ? err.message : String(err);
    process.stdout.write(JSON.stringify({ found: false, error: errMsg }));
    process.exit(1);
  }
})();

// ── Matching helpers ──────────────────────────────────────────────────────────

function mobileMatches(txMobile, enteredDigits) {
  // App sends masked numbers like "980****120" — only last 3 digits are reliable
  const td = (txMobile || "").replace(/\D/g, ""); // "980****120" → "980120"
  const ed = enteredDigits.replace(/\D/g, "").replace(/^977/, "").slice(-10);
  if (td.length < 3 || ed.length < 3) return false;
  return td.slice(-3) === ed.slice(-3);
}

function matchTransaction(list, mobileDigits, amountFloat) {
  if (!Array.isArray(list)) return { found: false, rrn: "", amount: "" };

  const cutoff = Date.now() - 10 * 60 * 1000; // 10 minutes

  for (const tx of list) {
    if (!tx || typeof tx !== "object") continue;

    // Status check
    const status = String(tx.status || tx.txStatus || tx.paymentStatus || "").toLowerCase();
    if (status && !status.includes("success") && !status.includes("complete")) continue;

    // Time check
    const txTimeRaw = tx.createdDate || tx.transactionDate || tx.date || tx.created_at || tx.txDate || "";
    if (txTimeRaw) {
      const txTime = new Date(txTimeRaw).getTime();
      if (txTime && txTime < cutoff) continue;
    }

    // Mobile match
    const txMobile = String(
      tx.mobile || tx.customerPhone || tx.phone || tx.mobileNumber || tx.debitAccountNumber || ""
    );
    if (!mobileMatches(txMobile, mobileDigits)) continue;

    // Amount match (±1 NPR tolerance)
    if (amountFloat > 0) {
      const txAmt = parseFloat(tx.amount || tx.txAmount || tx.collectionAmount || 0);
      if (Math.abs(txAmt - amountFloat) > 1.0) continue;
    }

    const rrn = String(tx.rrn || tx.transactionId || tx.txId || tx.id || "");
    return { found: true, rrn, amount: String(tx.amount || tx.txAmount || "") };
  }

  return { found: false, rrn: "", amount: "" };
}

function matchFromDomText(rows, mobileDigits, amountFloat) {
  if (!Array.isArray(rows)) return { found: false, rrn: "", amount: "" };

  const ed = mobileDigits.replace(/\D/g, "").slice(-10);
  const last3  = ed.slice(-3);
  const first3 = ed.slice(0, 3);

  for (const row of rows) {
    const text = String(row);
    if (!text) continue;

    // Check success status
    if (!/success|complete|paid/i.test(text)) continue;

    // Check mobile fragments
    const digits = text.replace(/\D/g, "");
    if (!digits.includes(last3) || !digits.includes(first3)) continue;

    // Check amount
    if (amountFloat > 0) {
      const nums = text.match(/[\d,]+\.?\d{0,2}/g) || [];
      const found = nums.some(n => Math.abs(parseFloat(n.replace(/,/g, "")) - amountFloat) <= 1.0);
      if (!found) continue;
    }

    // Extract RRN — long uppercase alphanum
    const rrnMatch = text.match(/\b[A-Z0-9]{8,24}\b/);
    return { found: true, rrn: rrnMatch ? rrnMatch[0] : "", amount: String(amountFloat || "") };
  }

  return { found: false, rrn: "", amount: "" };
}
