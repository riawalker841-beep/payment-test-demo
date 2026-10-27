<?php
/**
 * webhook.php
 *
 * Self-bootstrapping payment receiver for PayGate.
 * Upload this file alongside index.html, admin.html, storage.js to any
 * PHP 7.4+ host. No configuration required — it sets itself up on first run.
 *
 * Endpoints
 * ─────────────────────────────────────────────────────────────────────────────
 * POST /webhook.php                  Android PayChecker pushes payments
 * GET  /webhook.php                  Admin dashboard polls payment list
 * GET  /webhook.php?action=get_config   Get merchant config (QR image + name)
 * POST /webhook.php?action=set_config   Admin: save merchant config
 */

// ── Bootstrap ─────────────────────────────────────────────────────────────────
define('DATA_DIR', __DIR__ . '/data');
if (!is_dir(DATA_DIR)) {
    mkdir(DATA_DIR, 0755, true);
}

// ── Universal request logger (remove once issue is diagnosed) ─────────────────
$_rawBody = (string)file_get_contents('php://input');
$_logLine = '[' . date('c') . '] '
    . ($_SERVER['REQUEST_METHOD'] ?? '?') . ' '
    . ($_SERVER['REQUEST_URI']    ?? '?') . "\n"
    . 'IP: '      . ($_SERVER['REMOTE_ADDR']    ?? '?') . "\n"
    . 'UA: '      . ($_SERVER['HTTP_USER_AGENT'] ?? '(none)') . "\n"
    . 'CT: '      . ($_SERVER['CONTENT_TYPE']    ?? ($_SERVER['HTTP_CONTENT_TYPE'] ?? '(none)')) . "\n"
    . 'BODY: '    . (strlen($_rawBody) ? $_rawBody : '(empty)') . "\n"
    . str_repeat('-', 60) . "\n";
file_put_contents(DATA_DIR . '/debug.log', $_logLine, FILE_APPEND | LOCK_EX);

// ── CORS / headers ────────────────────────────────────────────────────────────
header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

// ── SQLite ────────────────────────────────────────────────────────────────────
$dbFile = DATA_DIR . '/payments.db';
try {
    $db = new PDO('sqlite:' . $dbFile, null, null, [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
    $db->exec('PRAGMA journal_mode=WAL');
    $db->exec('PRAGMA synchronous=NORMAL');
} catch (Throwable $e) {
    http_response_code(500);
    echo json_encode(['ok' => false, 'error' => 'Cannot open database', 'detail' => $e->getMessage()]);
    exit;
}

// Payments table
$db->exec("
    CREATE TABLE IF NOT EXISTS payments (
        id          TEXT PRIMARY KEY,
        amount      TEXT NOT NULL DEFAULT '',
        mobile      TEXT NOT NULL DEFAULT '',
        rrn         TEXT NOT NULL DEFAULT '',
        remarks     TEXT DEFAULT '',
        success     INTEGER NOT NULL DEFAULT 0,
        source      TEXT DEFAULT '',
        app_ts      INTEGER,
        received_at TEXT NOT NULL,
        claimed_at  TEXT DEFAULT NULL
    )
");
$db->exec("CREATE INDEX IF NOT EXISTS idx_received ON payments (received_at DESC)");
// Add claimed_at to existing databases that were created before this column existed
try {
    $db->exec("ALTER TABLE payments ADD COLUMN claimed_at TEXT DEFAULT NULL");
} catch (Throwable $_) { /* column already exists — ignore */ }

// Settings table (key/value — stores server-side config)
$db->exec("
    CREATE TABLE IF NOT EXISTS settings (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL DEFAULT ''
    )
");

// ── Settings helpers ──────────────────────────────────────────────────────────
function getSetting(PDO $db, string $key, string $default = ''): string {
    $s = $db->prepare("SELECT value FROM settings WHERE key=:k");
    $s->execute([':k' => $key]);
    $row = $s->fetch();
    return $row ? $row['value'] : $default;
}

function setSetting(PDO $db, string $key, string $value): void {
    $db->prepare("INSERT OR REPLACE INTO settings (key,value) VALUES (:k,:v)")
       ->execute([':k' => $key, ':v' => $value]);
}

// ── Admin sessions table ──────────────────────────────────────────────────────
$db->exec("
    CREATE TABLE IF NOT EXISTS admin_sessions (
        token      TEXT PRIMARY KEY,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL
    )
");

// ── TOTP (RFC 6238) — pure PHP, no dependencies ───────────────────────────────
function totpBase32Decode(string $base32): string {
    $base32 = strtoupper(str_replace('=', '', $base32));
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $bits = '';
    foreach (str_split($base32) as $char) {
        $pos = strpos($alphabet, $char);
        if ($pos === false) continue;
        $bits .= str_pad(decbin($pos), 5, '0', STR_PAD_LEFT);
    }
    $bytes = '';
    foreach (str_split($bits, 8) as $chunk) {
        if (strlen($chunk) === 8) $bytes .= chr(bindec($chunk));
    }
    return $bytes;
}

function totpGenerate(string $secret, int $timestamp = 0, int $window = 0): string {
    if ($timestamp === 0) $timestamp = time();
    $counter = pack('N*', 0) . pack('N*', (int)floor(($timestamp + $window * 30) / 30));
    $key  = totpBase32Decode($secret);
    $hash = hash_hmac('sha1', $counter, $key, true);
    $offset = ord($hash[19]) & 0x0F;
    $code = (
        ((ord($hash[$offset])   & 0x7F) << 24) |
        ((ord($hash[$offset+1]) & 0xFF) << 16) |
        ((ord($hash[$offset+2]) & 0xFF) << 8)  |
        ( ord($hash[$offset+3]) & 0xFF)
    ) % 1000000;
    return str_pad((string)$code, 6, '0', STR_PAD_LEFT);
}

function totpVerify(string $secret, string $code): bool {
    $code = trim($code);
    if (!preg_match('/^\d{6}$/', $code)) return false;
    // Allow ±1 window (30s drift tolerance)
    foreach ([-1, 0, 1] as $w) {
        if (hash_equals(totpGenerate($secret, time(), $w), $code)) return true;
    }
    return false;
}

function totpGenerateSecret(): string {
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $secret = '';
    for ($i = 0; $i < 32; $i++) {
        $secret .= $alphabet[random_int(0, 31)];
    }
    return $secret;
}

function totpQrUri(string $secret, string $issuer = 'PayGate Admin'): string {
    $label = rawurlencode($issuer);
    return "otpauth://totp/{$label}?secret={$secret}&issuer={$label}&algorithm=SHA1&digits=6&period=30";
}

// ── Session helpers ───────────────────────────────────────────────────────────
define('SESSION_TTL', 8 * 3600); // 8 hours

function createAdminSession(PDO $db): string {
    $token = bin2hex(random_bytes(32));
    $now   = time();
    $db->prepare("INSERT INTO admin_sessions (token,created_at,expires_at) VALUES (:t,:c,:e)")
       ->execute([':t' => $token, ':c' => $now, ':e' => $now + SESSION_TTL]);
    // Prune expired sessions
    $db->exec("DELETE FROM admin_sessions WHERE expires_at < " . ($now - 60));
    return $token;
}

function validateAdminSession(PDO $db, string $token): bool {
    if (!preg_match('/^[a-f0-9]{64}$/', $token)) return false;
    $s = $db->prepare("SELECT expires_at FROM admin_sessions WHERE token=:t");
    $s->execute([':t' => $token]);
    $row = $s->fetch();
    return $row && (int)$row['expires_at'] > time();
}

// ── Auth middleware — protect sensitive actions ───────────────────────────────
function requireAuth(PDO $db): void {
    $token = trim($_SERVER['HTTP_X_ADMIN_TOKEN'] ?? $_GET['admin_token'] ?? '');
    if (!validateAdminSession($db, $token)) {
        http_response_code(401);
        echo json_encode(['ok' => false, 'error' => 'Unauthorized', 'code' => 'AUTH_REQUIRED']);
        exit;
    }
}

// ── Action routing ────────────────────────────────────────────────────────────
$action = trim($_GET['action'] ?? '');
$method = $_SERVER['REQUEST_METHOD'];

// ── POST: admin login (password + TOTP) ───────────────────────────────────────
if ($method === 'POST' && $action === 'admin_login') {
    $data     = json_decode((string)file_get_contents('php://input'), true) ?? [];
    $password = trim((string)($data['password'] ?? ''));
    $totpCode = trim((string)($data['totp']     ?? ''));

    $storedHash   = getSetting($db, 'admin_password_hash');
    $storedSecret = getSetting($db, 'admin_totp_secret');

    // Not yet set up
    if ($storedHash === '' || $storedSecret === '') {
        echo json_encode(['ok' => false, 'error' => 'Admin not set up yet. Open setup_admin.php first.', 'code' => 'NOT_SETUP']);
        exit;
    }

    if (!password_verify($password, $storedHash)) {
        http_response_code(401);
        echo json_encode(['ok' => false, 'error' => 'Incorrect password.', 'code' => 'BAD_PASSWORD']);
        exit;
    }

    if (!totpVerify($storedSecret, $totpCode)) {
        http_response_code(401);
        echo json_encode(['ok' => false, 'error' => 'Invalid authenticator code.', 'code' => 'BAD_TOTP']);
        exit;
    }

    $token = createAdminSession($db);
    echo json_encode(['ok' => true, 'token' => $token, 'expires_in' => SESSION_TTL]);
    exit;
}

// ── POST: admin logout ────────────────────────────────────────────────────────
if ($method === 'POST' && $action === 'admin_logout') {
    $data  = json_decode((string)file_get_contents('php://input'), true) ?? [];
    $token = trim((string)($data['token'] ?? $_SERVER['HTTP_X_ADMIN_TOKEN'] ?? ''));
    if (preg_match('/^[a-f0-9]{64}$/', $token)) {
        $db->prepare("DELETE FROM admin_sessions WHERE token=:t")->execute([':t' => $token]);
    }
    echo json_encode(['ok' => true]);
    exit;
}

// ── GET: check session validity ───────────────────────────────────────────────
if ($method === 'GET' && $action === 'admin_check') {
    $token = trim($_GET['token'] ?? $_SERVER['HTTP_X_ADMIN_TOKEN'] ?? '');
    $setup = getSetting($db, 'admin_password_hash') !== '' && getSetting($db, 'admin_totp_secret') !== '';
    echo json_encode([
        'ok'       => true,
        'valid'    => validateAdminSession($db, $token),
        'setup'    => $setup,
    ]);
    exit;
}

// ── GET: merchant config (public — customer page needs this) ──────────────────
if ($method === 'GET' && $action === 'get_config') {
    // Prevent any proxy or CDN from caching this — every device must get fresh data
    header('Cache-Control: no-store, no-cache, must-revalidate');
    header('Pragma: no-cache');
    echo json_encode([
        'ok'              => true,
        'merchantName'    => getSetting($db, 'cfg_merchant_name', 'My Store'),
        'qrImage'         => getSetting($db, 'cfg_qr_image', ''),
        'nepalpayQrImage' => getSetting($db, 'cfg_nepalpay_qr_image', ''),
    ]);
    exit;
}

// ── POST: heartbeat from Android device (no auth needed) ─────────────────────
if ($method === 'POST' && $action === 'heartbeat') {
    // Accept silently — just acknowledge
    echo json_encode(['ok' => true, 'server_time' => date('c')]);
    exit;
}

// ── POST: save merchant config (auth required) ───────────────────────────────
if ($method === 'POST' && $action === 'set_config') {
    requireAuth($db);
    $data = json_decode((string)file_get_contents('php://input'), true) ?? [];

    // If json_decode returned null the body was likely truncated by PHP's
    // post_max_size limit — refuse rather than silently wiping saved QRs.
    if (!is_array($data)) {
        http_response_code(413);
        echo json_encode(['ok' => false, 'error' => 'Request body too large or malformed. Check PHP post_max_size.']);
        exit;
    }

    $name  = trim((string)($data['merchantName']    ?? ''));
    $qr    = isset($data['qrImage'])         ? (string)$data['qrImage']         : null;
    $nqr   = isset($data['nepalpayQrImage'])  ? (string)$data['nepalpayQrImage']  : null;

    if ($name === '') {
        http_response_code(400);
        echo json_encode(['ok' => false, 'error' => 'merchantName is required']);
        exit;
    }

    // Validate image values when present
    foreach (['qrImage' => $qr, 'nepalpayQrImage' => $nqr] as $field => $val) {
        if ($val !== null && $val !== '' && strpos($val, 'data:image/') !== 0 && strpos($val, 'http') !== 0) {
            http_response_code(400);
            echo json_encode(['ok' => false, 'error' => 'Invalid ' . $field . ' value']);
            exit;
        }
    }

    // Always save merchant name
    setSetting($db, 'cfg_merchant_name', $name);

    // Only overwrite QR fields when they were explicitly included in the request.
    // A null value means the field was omitted — keep whatever is already stored.
    // An empty string means the admin clicked "Remove" — clear it.
    if ($qr !== null)  setSetting($db, 'cfg_qr_image',          $qr);
    if ($nqr !== null) setSetting($db, 'cfg_nepalpay_qr_image',  $nqr);

    echo json_encode(['ok' => true]);
    exit;
}

// ── GET: read debug log (admin only) ─────────────────────────────────────────
if ($method === 'GET' && $action === 'debug_log') {
    requireAuth($db);
    $logFile = DATA_DIR . '/debug.log';
    if (!file_exists($logFile)) {
        echo json_encode(['ok' => true, 'log' => 'No log yet. Trigger a payment from the Android app first.']);
        exit;
    }
    // Return last 8 KB of the log
    $size    = filesize($logFile);
    $handle  = fopen($logFile, 'r');
    if ($size > 8192) fseek($handle, $size - 8192);
    $content = fread($handle, 8192);
    fclose($handle);
    echo json_encode(['ok' => true, 'log' => $content, 'size' => $size]);
    exit;
}

// ── GET: clear debug log (admin only) ────────────────────────────────────────
if ($method === 'POST' && $action === 'clear_debug_log') {
    requireAuth($db);
    @unlink(DATA_DIR . '/debug.log');
    echo json_encode(['ok' => true]);
    exit;
}
// Returns only unclaimed payments: mobile, amount, success, received_at, id.
if ($method === 'GET' && $action === 'poll_payments') {
    $limit = min(max((int)($_GET['limit'] ?? 50), 1), 50);
    $stmt  = $db->prepare("
        SELECT id, mobile, amount, success, received_at
        FROM   payments
        WHERE  claimed_at IS NULL
        ORDER  BY received_at DESC
        LIMIT  :lim
    ");
    $stmt->bindValue(':lim', $limit, PDO::PARAM_INT);
    $stmt->execute();
    $rows = $stmt->fetchAll();
    foreach ($rows as &$r) {
        $r['success'] = (bool)(int)$r['success'];
    }
    unset($r);
    echo json_encode(['ok' => true, 'payments' => $rows]);
    exit;
}

// ── POST: claim a payment (customer page marks it as used) ────────────────────
// No auth needed — but the caller must supply the correct payment id.
// Once claimed, the record disappears from poll_payments so it can't match again.
if ($method === 'POST' && $action === 'claim_payment') {
    $data = json_decode((string)file_get_contents('php://input'), true) ?? [];
    $id   = trim((string)($data['id'] ?? ''));
    if (!$id) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'error' => 'Missing id']);
        exit;
    }
    $stmt = $db->prepare("
        UPDATE payments
        SET    claimed_at = :now
        WHERE  id = :id AND claimed_at IS NULL
    ");
    $stmt->execute([':now' => date('c'), ':id' => $id]);
    echo json_encode(['ok' => true, 'claimed' => $stmt->rowCount() > 0]);
    exit;
}

// ── GET: payment list (auth required for admin) ───────────────────────────────
if ($method === 'GET') {
    requireAuth($db);
    $since = isset($_GET['since']) ? trim($_GET['since']) : null;
    $limit = min(max((int)($_GET['limit'] ?? 200), 1), 500);

    if ($since) {
        $stmt = $db->prepare("SELECT * FROM payments WHERE received_at>:since ORDER BY received_at DESC LIMIT :lim");
        $stmt->bindValue(':since', $since);
        $stmt->bindValue(':lim', $limit, PDO::PARAM_INT);
        $stmt->execute();
    } else {
        $stmt = $db->prepare("SELECT * FROM payments ORDER BY received_at DESC LIMIT :lim");
        $stmt->bindValue(':lim', $limit, PDO::PARAM_INT);
        $stmt->execute();
    }

    $rows = $stmt->fetchAll();
    foreach ($rows as &$r) {
        $r['success'] = (bool)(int)$r['success'];
        $r['app_ts']  = $r['app_ts'] !== null ? (int)$r['app_ts'] : null;
    }
    unset($r);

    $totals = $db->query("
        SELECT COUNT(*) AS total,
               SUM(CASE WHEN success=1 THEN 1 ELSE 0 END) AS successful,
               SUM(CASE WHEN success=0 THEN 1 ELSE 0 END) AS failed
        FROM payments
    ")->fetch();

    echo json_encode([
        'ok'          => true,
        'payments'    => $rows,
        'count'       => count($rows),
        'totals'      => [
            'total'      => (int)$totals['total'],
            'successful' => (int)$totals['successful'],
            'failed'     => (int)$totals['failed'],
        ],
        'server_time' => date('c'),
    ]);
    exit;
}

// ── POST: receive a payment from Android app ──────────────────────────────────
if ($method !== 'POST') {
    http_response_code(405);
    echo json_encode(['ok' => false, 'error' => 'Method not allowed']);
    exit;
}

$rawBody = $_rawBody; // already read at top
$data    = json_decode($rawBody, true);

// (debug logging now handled at the top of the file)

if (!is_array($data) || empty($data['mobile']) || !isset($data['amount']) || empty($data['rrn'])) {
    $rejectReason = !is_array($data) ? 'not_json'
        : (empty($data['mobile'])  ? 'missing_mobile'
        : (!isset($data['amount']) ? 'missing_amount'
        :                            'missing_rrn'));
    file_put_contents(DATA_DIR . '/debug.log', '[' . date('c') . '] REJECTED: ' . $rejectReason . "\n" . str_repeat('-', 60) . "\n", FILE_APPEND | LOCK_EX);
    http_response_code(400);
    echo json_encode(['ok' => false, 'error' => 'Missing required fields: mobile, amount, rrn', 'hint' => $rejectReason]);
    exit;
}

$id = uniqid('PAY', true);
$db->prepare("
    INSERT OR IGNORE INTO payments
        (id, amount, mobile, rrn, remarks, success, source, app_ts, received_at)
    VALUES (:id,:amount,:mobile,:rrn,:remarks,:success,:source,:app_ts,:received_at)
")->execute([
    ':id'          => $id,
    ':amount'      => substr((string)$data['amount'],          0, 32),
    ':mobile'      => substr((string)$data['mobile'],          0, 20),
    ':rrn'         => substr((string)$data['rrn'],             0, 64),
    ':remarks'     => substr((string)($data['remarks'] ?? ''), 0, 128),
    ':success'     => !empty($data['success']) ? 1 : 0,
    ':source'      => substr((string)($data['source']  ?? ''), 0, 128),
    ':app_ts'      => isset($data['timestamp']) ? (int)$data['timestamp'] : null,
    ':received_at' => date('c'),
]);

http_response_code(201);
echo json_encode(['ok' => true, 'id' => $id]);
