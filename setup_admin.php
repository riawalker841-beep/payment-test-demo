<?php
/**
 * setup_admin.php
 *
 * Admin credentials setup / update for PayGate.
 * ─────────────────────────────────────────────
 * First run  : set password + scan TOTP QR into your authenticator app.
 * Later runs : verify current password before making any changes.
 *
 * Keep this file on the server (it is now protected by the current password).
 * Anyone without the current password cannot change credentials.
 */

define('DATA_DIR', __DIR__ . '/data');
if (!is_dir(DATA_DIR)) mkdir(DATA_DIR, 0755, true);

// ── DB ────────────────────────────────────────────────────────────────────────
$dbFile = DATA_DIR . '/payments.db';
try {
    $db = new PDO('sqlite:' . $dbFile, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    $db->exec("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL DEFAULT '')");
    $db->exec("CREATE TABLE IF NOT EXISTS admin_sessions (token TEXT PRIMARY KEY, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL)");
} catch (Throwable $e) {
    die("DB error: " . htmlspecialchars($e->getMessage()));
}

function getSetting(PDO $db, string $key): string {
    $r = $db->query("SELECT value FROM settings WHERE key=" . $db->quote($key))->fetchColumn();
    return $r !== false ? (string)$r : '';
}
function setSetting(PDO $db, string $key, string $value): void {
    $db->prepare("INSERT OR REPLACE INTO settings (key,value) VALUES (:k,:v)")
       ->execute([':k' => $key, ':v' => $value]);
}

// ── TOTP helpers ──────────────────────────────────────────────────────────────
function totpBase32Decode(string $b32): string {
    $b32   = strtoupper(str_replace('=', '', $b32));
    $alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $bits  = '';
    foreach (str_split($b32) as $c) {
        $p = strpos($alpha, $c);
        if ($p === false) continue;
        $bits .= str_pad(decbin($p), 5, '0', STR_PAD_LEFT);
    }
    $out = '';
    foreach (str_split($bits, 8) as $chunk) {
        if (strlen($chunk) === 8) $out .= chr(bindec($chunk));
    }
    return $out;
}
function totpGenerate(string $secret, int $ts = 0, int $win = 0): string {
    if (!$ts) $ts = time();
    $ctr  = pack('N*', 0) . pack('N*', (int)floor(($ts + $win * 30) / 30));
    $key  = totpBase32Decode($secret);
    $h    = hash_hmac('sha1', $ctr, $key, true);
    $off  = ord($h[19]) & 0x0F;
    $code = (((ord($h[$off]) & 0x7F) << 24) | ((ord($h[$off+1]) & 0xFF) << 16)
           | ((ord($h[$off+2]) & 0xFF) << 8)  |  (ord($h[$off+3]) & 0xFF)) % 1000000;
    return str_pad((string)$code, 6, '0', STR_PAD_LEFT);
}
function totpVerify(string $secret, string $code): bool {
    if (!preg_match('/^\d{6}$/', trim($code))) return false;
    foreach ([-1, 0, 1] as $w) {
        if (hash_equals(totpGenerate($secret, time(), $w), trim($code))) return true;
    }
    return false;
}
function totpGenerateSecret(): string {
    $a = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $s = '';
    for ($i = 0; $i < 32; $i++) $s .= $a[random_int(0, 31)];
    return $s;
}

// ── State ─────────────────────────────────────────────────────────────────────
$alreadySetup   = getSetting($db, 'admin_password_hash') !== '';
$verified2fa    = getSetting($db, 'admin_totp_verified') === '1';

$message        = '';
$messageType    = '';
$showQr         = false;
$totpSecret     = '';
$totpUri        = '';

// Which UI panel to show:
// 'verify_current' — ask for current password (when already set up)
// 'set_new'        — set new password + regenerate QR
// 'verify_totp'    — scan QR + enter code to confirm
// 'done'           — all done
$panel = $alreadySetup ? 'verify_current' : 'set_new';

// Session-style flag stored in PHP session so we don't re-check each POST
session_start();

// ── Handle POST ───────────────────────────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $step = trim($_POST['step'] ?? '');

    // ── Step: verify current password before allowing changes ─────────────────
    if ($step === 'verify_current') {
        $currentPw    = $_POST['current_password'] ?? '';
        $storedHash   = getSetting($db, 'admin_password_hash');

        if (!password_verify($currentPw, $storedHash)) {
            $message     = 'Incorrect current password.';
            $messageType = 'error';
            $panel       = 'verify_current';
        } else {
            // Mark as verified in session so the next form can proceed
            $_SESSION['setup_auth'] = true;
            $panel       = 'set_new';
        }
    }

    // ── Step: save new password + (re)generate TOTP secret ───────────────────
    if ($step === 'set_password') {
        // Require current-password verification for existing setups
        if ($alreadySetup && empty($_SESSION['setup_auth'])) {
            $message     = 'Please verify your current password first.';
            $messageType = 'error';
            $panel       = 'verify_current';
        } else {
            $pw  = $_POST['password']  ?? '';
            $pw2 = $_POST['password2'] ?? '';

            if (strlen($pw) < 8) {
                $message     = 'New password must be at least 8 characters.';
                $messageType = 'error';
                $panel       = 'set_new';
            } elseif ($pw !== $pw2) {
                $message     = 'Passwords do not match.';
                $messageType = 'error';
                $panel       = 'set_new';
            } else {
                // Always regenerate the TOTP secret when credentials are updated
                $secret = totpGenerateSecret();
                $label  = rawurlencode('PayGate Admin');
                setSetting($db, 'admin_totp_secret',   $secret);
                setSetting($db, 'admin_totp_verified', '0'); // must re-verify
                setSetting($db, 'admin_password_hash', password_hash($pw, PASSWORD_BCRYPT, ['cost' => 12]));
                // Invalidate all existing sessions
                $db->exec("DELETE FROM admin_sessions WHERE 1");

                $totpSecret  = $secret;
                $totpUri     = "otpauth://totp/{$label}?secret={$secret}&issuer={$label}&algorithm=SHA1&digits=6&period=30";
                $showQr      = true;
                $panel       = 'verify_totp';
                $message     = 'Password saved. Scan the QR code into your authenticator app, then enter a code to confirm.';
                $messageType = 'success';
            }
        }
    }

    // ── Step: verify TOTP code after scanning ─────────────────────────────────
    if ($step === 'verify_totp') {
        $code   = trim($_POST['totp_code'] ?? '');
        $secret = getSetting($db, 'admin_totp_secret');

        // Re-show QR on failure
        $totpSecret = $secret;
        $label      = rawurlencode('PayGate Admin');
        $totpUri    = "otpauth://totp/{$label}?secret={$secret}&issuer={$label}&algorithm=SHA1&digits=6&period=30";
        $showQr     = true;
        $panel      = 'verify_totp';

        if (totpVerify($secret, $code)) {
            setSetting($db, 'admin_totp_verified', '1');
            unset($_SESSION['setup_auth']); // clear the session flag
            $message     = '✓ 2FA verified and active. Your credentials have been updated.';
            $messageType = 'done';
            $panel       = 'done';
        } else {
            $message     = 'Incorrect code — check the time on your device and try again.';
            $messageType = 'error';
        }
    }
} else {
    // GET — if a TOTP secret exists but isn't verified yet, show the QR again
    $existingSecret = getSetting($db, 'admin_totp_secret');
    if ($existingSecret && getSetting($db, 'admin_totp_verified') !== '1') {
        $totpSecret = $existingSecret;
        $label      = rawurlencode('PayGate Admin');
        $totpUri    = "otpauth://totp/{$label}?secret={$totpSecret}&issuer={$label}&algorithm=SHA1&digits=6&period=30";
        $showQr     = true;
        $panel      = 'verify_totp';
    }
}
?><!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PayGate — Admin Setup</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
       background:#0f172a;color:#f8fafc;min-height:100vh;
       display:flex;align-items:center;justify-content:center;padding:1.5rem}
  .card{background:#1e293b;border-radius:20px;padding:2rem;width:100%;max-width:500px;
        border:1px solid rgba(255,255,255,0.08);box-shadow:0 25px 60px rgba(0,0,0,.5)}
  .brand{display:flex;align-items:center;gap:.6rem;margin-bottom:1.75rem}
  .brand-icon{width:40px;height:40px;border-radius:12px;
              background:linear-gradient(135deg,#1d4ed8,#2563eb);
              display:flex;align-items:center;justify-content:center;
              box-shadow:0 4px 14px rgba(37,99,235,.4)}
  .brand-icon svg{width:22px;height:22px}
  h1{font-size:1.1rem;margin:0;font-weight:800;color:#f8fafc}
  .sub-brand{font-size:.72rem;color:#64748b}
  .panel-title{font-size:1.05rem;font-weight:700;color:#e2e8f0;margin-bottom:.3rem}
  .panel-desc{font-size:.82rem;color:#64748b;margin-bottom:1.5rem;line-height:1.5}
  label{display:block;font-size:.75rem;font-weight:700;color:#94a3b8;
        margin:.85rem 0 .35rem;text-transform:uppercase;letter-spacing:.5px}
  input[type=password],input[type=text]{
    width:100%;background:#0f172a;border:1.5px solid #334155;border-radius:10px;
    padding:.7rem .9rem;font-size:.95rem;color:#f8fafc;outline:none;
    transition:border-color .15s,box-shadow .15s}
  input:focus{border-color:#2563eb;box-shadow:0 0 0 3px rgba(37,99,235,.25)}
  .btn{width:100%;border:none;border-radius:10px;padding:.8rem;font-size:.95rem;
       font-weight:700;cursor:pointer;margin-top:1.25rem;transition:all .15s}
  .btn-primary{background:linear-gradient(135deg,#2563eb,#1d4ed8);color:#fff;
               box-shadow:0 4px 12px rgba(37,99,235,.4)}
  .btn-primary:hover{box-shadow:0 6px 18px rgba(37,99,235,.5);transform:translateY(-1px)}
  .msg{margin-top:1rem;padding:.75rem 1rem;border-radius:10px;font-size:.85rem;font-weight:600;line-height:1.45}
  .msg.error  {background:rgba(220,38,38,.15);color:#f87171;border:1px solid rgba(220,38,38,.3)}
  .msg.success{background:rgba(37,99,235,.15);color:#93c5fd;border:1px solid rgba(37,99,235,.3)}
  .msg.done   {background:rgba(22,163,74,.15);color:#4ade80;border:1px solid rgba(22,163,74,.3)}
  .qr-section{margin-top:1.5rem;background:#0f172a;border-radius:14px;padding:1.25rem;
              text-align:center;border:1px solid #334155}
  .qr-section h3{font-size:.88rem;font-weight:700;margin-bottom:.75rem;color:#e2e8f0}
  .qr-wrap{background:#fff;padding:12px;border-radius:10px;display:inline-block;margin-bottom:.75rem}
  .qr-wrap img{display:block;width:180px;height:180px}
  .secret-code{font-family:ui-monospace,monospace;font-size:.88rem;background:#1e293b;
               border:1px solid #334155;border-radius:8px;padding:.5rem .75rem;
               color:#7dd3fc;letter-spacing:2px;word-break:break-all;margin:.5rem 0 1rem}
  .step-badge{display:inline-block;background:#2563eb;color:#fff;border-radius:999px;
              padding:.15rem .65rem;font-size:.7rem;font-weight:700;margin-bottom:.5rem}
  .divider{height:1px;background:#334155;border:none;margin:1.5rem 0}
  .warn{background:rgba(245,158,11,.1);border:1px solid rgba(245,158,11,.3);
        color:#fbbf24;border-radius:10px;padding:.65rem .9rem;font-size:.82rem;margin-top:1rem;line-height:1.45}
  .lock-icon{font-size:2rem;text-align:center;margin-bottom:.75rem}
  .totp-input{text-align:center;font-size:1.5rem;letter-spacing:8px;font-weight:700}
  code{background:#0f172a;padding:.1rem .4rem;border-radius:5px;font-size:.82rem;color:#7dd3fc}
</style>
</head>
<body>
<div class="card">

  <!-- Brand -->
  <div class="brand">
    <div class="brand-icon">
      <svg viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
        <rect x="2" y="5" width="20" height="14" rx="3"/><path d="M2 10h20"/>
      </svg>
    </div>
    <div>
      <h1>PayGate Admin</h1>
      <div class="sub-brand">Credentials Setup</div>
    </div>
  </div>

  <?php if ($panel === 'done'): ?>
  <!-- ── Done ── -->
  <div class="lock-icon">✅</div>
  <div class="msg done"><?= htmlspecialchars($message) ?></div>
  <div class="warn">
    Your new credentials are active. All existing admin sessions have been invalidated —
    sign in again at <code>admin.html</code> with your new password and refreshed authenticator code.
  </div>

  <?php elseif ($panel === 'verify_current'): ?>
  <!-- ── Verify current password ── -->
  <div class="lock-icon">🔒</div>
  <div class="panel-title">Verify current password</div>
  <div class="panel-desc">Enter your existing admin password to continue. This protects your credentials from unauthorised changes.</div>

  <?php if ($message): ?>
    <div class="msg <?= $messageType ?>"><?= htmlspecialchars($message) ?></div>
  <?php endif ?>

  <form method="POST" autocomplete="off">
    <input type="hidden" name="step" value="verify_current">
    <label for="cur_pw">Current password</label>
    <input type="password" id="cur_pw" name="current_password"
           placeholder="Your existing password" autocomplete="current-password">
    <button type="submit" class="btn btn-primary">Verify &amp; Continue &rarr;</button>
  </form>

  <?php elseif ($panel === 'set_new'): ?>
  <!-- ── Set new password ── -->
  <span class="step-badge">Step 1 of 3</span>
  <div class="panel-title">Set admin password</div>
  <div class="panel-desc">Choose a strong password. A new authenticator QR will be generated — you'll need to re-scan it.</div>

  <?php if ($message): ?>
    <div class="msg <?= $messageType ?>"><?= htmlspecialchars($message) ?></div>
  <?php endif ?>

  <form method="POST" autocomplete="off">
    <input type="hidden" name="step" value="set_password">
    <label for="pw">New password</label>
    <input type="password" id="pw" name="password"
           placeholder="Minimum 8 characters" autocomplete="new-password">
    <label for="pw2">Confirm new password</label>
    <input type="password" id="pw2" name="password2"
           placeholder="Repeat password" autocomplete="new-password">
    <button type="submit" class="btn btn-primary">Save &amp; Generate QR &rarr;</button>
  </form>

  <?php elseif ($panel === 'verify_totp'): ?>
  <!-- ── Scan QR + verify TOTP ── -->
  <?php if ($message): ?>
    <div class="msg <?= $messageType ?>"><?= htmlspecialchars($message) ?></div>
  <?php endif ?>

  <?php if ($showQr && $totpUri): ?>
  <div class="qr-section">
    <span class="step-badge">Step 2 of 3</span>
    <h3>Scan into Google Authenticator / Authy</h3>
    <div class="qr-wrap">
      <img src="https://api.qrserver.com/v1/create-qr-code/?size=180x180&data=<?= rawurlencode($totpUri) ?>"
           alt="TOTP QR Code" />
    </div>
    <p style="font-size:.78rem;color:#94a3b8;margin-bottom:.3rem">Or enter this secret manually:</p>
    <div class="secret-code"><?= htmlspecialchars(chunk_split($totpSecret, 4, ' ')) ?></div>

    <hr class="divider">

    <span class="step-badge">Step 3 of 3</span>
    <h3 style="margin-top:.5rem">Confirm with a code</h3>
    <p style="font-size:.78rem;color:#64748b;margin:.5rem 0 .75rem">Open your authenticator app and enter the current 6-digit code.</p>
    <form method="POST">
      <input type="hidden" name="step" value="verify_totp">
      <input type="text" name="totp_code" class="totp-input"
             placeholder="000000" inputmode="numeric"
             maxlength="6" autocomplete="one-time-code">
      <button type="submit" class="btn btn-primary">Verify &amp; Activate &rarr;</button>
    </form>
  </div>
  <?php endif ?>

  <?php endif ?>

</div>
</body>
</html>
