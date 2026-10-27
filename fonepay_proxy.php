<?php
/**
 * fonepay_proxy.php
 *
 * Server-side relay for FonePay last-mile verification.
 * Uses the exact corporate-kong.fonepay.com API endpoints discovered
 * from network inspection of fonebiz.fonepay.com.
 *
 * Endpoints:
 *   GET  ?action=fp_status    → { ok, configured }
 *   POST ?action=fp_login     → { ok, session_token }
 *   POST ?action=fp_get_txns  { session_token, mobile, amount } → { ok, found, rrn, amount }
 */

header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(204); exit; }

// ── Constants ─────────────────────────────────────────────────────────────────
define('DATA_DIR', __DIR__ . '/data');
define('FP_LOGIN_URL',
    'https://corporate-kong.fonepay.com/corporate/auth/authentication/corporate-login');
define('FP_TXN_URL',
    'https://corporate-kong.fonepay.com/corporate/api/v1/merchant-collection/collections/transactions/filtered');
define('FP_CLIENT_CODE',    'CORPORATE_USER');
define('FP_CORPORATE_CODE', 'T75VHJG5U');
define('FP_MERCHANT_ID',    492292);

if (!is_dir(DATA_DIR)) mkdir(DATA_DIR, 0755, true);

// ── DB helpers ────────────────────────────────────────────────────────────────
function openDb(): PDO {
    $db = new PDO('sqlite:' . DATA_DIR . '/payments.db', null, null,
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    $db->exec("CREATE TABLE IF NOT EXISTS settings
               (key TEXT PRIMARY KEY, value TEXT NOT NULL DEFAULT '')");
    return $db;
}

function getSetting(string $key, string $default = ''): string {
    try {
        $db  = openDb();
        $val = $db->query("SELECT value FROM settings WHERE key=" . $db->quote($key))
                  ->fetchColumn();
        return $val !== false ? (string)$val : $default;
    } catch (Throwable $e) { return $default; }
}

function saveVerifiedPayment(string $mobile, string $amount, string $rrn): void {
    try {
        $db = openDb();
        $db->exec("CREATE TABLE IF NOT EXISTS payments (
            id TEXT PRIMARY KEY, amount TEXT NOT NULL DEFAULT '',
            mobile TEXT NOT NULL DEFAULT '', rrn TEXT NOT NULL DEFAULT '',
            remarks TEXT DEFAULT '', success INTEGER NOT NULL DEFAULT 0,
            source TEXT DEFAULT '', app_ts INTEGER, received_at TEXT NOT NULL)");
        $id = uniqid('FPV', true);
        $db->prepare("INSERT OR IGNORE INTO payments
            (id,amount,mobile,rrn,remarks,success,source,app_ts,received_at)
            VALUES (:id,:amount,:mobile,:rrn,'Last-mile FonePay verification',1,'fonepay_fallback',NULL,:ra)")
           ->execute([':id'=>$id, ':amount'=>substr($amount,0,32),
                      ':mobile'=>substr($mobile,0,20), ':rrn'=>substr($rrn,0,64),
                      ':ra'=>date('c')]);
    } catch (Throwable $e) {}
}

// ── cURL helper ───────────────────────────────────────────────────────────────
function fpCurl(string $url, string $method, ?array $body, string $cookieFile): array {
    $ch = curl_init($url);
    $headers = [
        'Content-Type: application/json',
        'Accept: application/json, text/plain, */*',
        'Accept-Language: en-US,en;q=0.9',
        'Origin: https://fonebiz.fonepay.com',
        'Referer: https://fonebiz.fonepay.com/',
        'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) ' .
            'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    ];
    $opts = [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => false,   // don't follow — we want the Set-Cookie header
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_TIMEOUT        => 25,
        CURLOPT_HTTPHEADER     => $headers,
        CURLOPT_HEADER         => false,
        CURLOPT_COOKIEJAR      => $cookieFile,
        CURLOPT_COOKIEFILE     => $cookieFile,
    ];
    if ($method === 'POST') {
        $opts[CURLOPT_POST]       = true;
        $opts[CURLOPT_POSTFIELDS] = json_encode($body);
    }
    curl_setopt_array($ch, $opts);
    $resp = (string)curl_exec($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err  = curl_error($ch);
    curl_close($ch);
    if ($err) return ['code' => 0, 'body' => '', 'error' => $err];
    return ['code' => $code, 'body' => $resp, 'error' => ''];
}

// ── Session helpers ───────────────────────────────────────────────────────────
function sessionBase(string $token): string {
    if (!preg_match('/^[a-f0-9]{32}$/', $token)) return '';
    return DATA_DIR . '/fp_sess_' . $token;
}

function readSession(string $token): array {
    $base = sessionBase($token);
    if (!$base || !file_exists($base . '.json')) return [];
    $d = json_decode((string)file_get_contents($base . '.json'), true);
    if (!is_array($d)) return [];
    if (isset($d['created']) && time() - $d['created'] > 600) {
        @unlink($base . '.json'); @unlink($base . '.cookies'); return [];
    }
    return $d;
}

function writeSession(string $token, array $data): void {
    $base = sessionBase($token);
    if (!$base) return;
    $data['created'] = $data['created'] ?? time();
    file_put_contents($base . '.json', json_encode($data));
}

function purgeOldSessions(): void {
    foreach (glob(DATA_DIR . '/fp_sess_*.json') ?: [] as $f) {
        if (filemtime($f) < time() - 900) {
            @unlink($f); @unlink(str_replace('.json', '.cookies', $f));
        }
    }
}

// ── Mobile matching (handles masked numbers like 97****8884) ──────────────────
function mobileMatches(string $txMobile, string $entered): bool {
    $td = preg_replace('/\D/', '', $txMobile);
    $ed = preg_replace('/\D/', '', $entered);
    $td = preg_replace('/^977/', '', $td);
    $ed = preg_replace('/^977/', '', $ed);
    if (strlen($td) < 3 || strlen($ed) < 3) return false;
    // FonePay masks middle digits: "97****8884" → first 2 + last 4 visible
    // We match last 4 digits and first 2 digits
    return substr($td, -4) === substr($ed, -4) && substr($td, 0, 2) === substr($ed, 0, 2);
}

// ── Transaction matching ──────────────────────────────────────────────────────
function findInTransactions(array $list, string $mobile, float $amount): array {
    $cutoff = time() - 600; // 10-minute window

    // Pass 1: mobile + amount match
    foreach ($list as $tx) {
        if (!is_array($tx)) continue;
        if (strtolower((string)($tx['paymentStatus'] ?? '')) !== 'success') continue;
        $txTime = strtotime((string)($tx['transactionDate'] ?? ''));
        if ($txTime && $txTime < $cutoff) continue;
        if (!mobileMatches((string)($tx['customerMobile'] ?? ''), $mobile)) continue;
        if ($amount > 0 && abs((float)($tx['amount'] ?? 0) - $amount) > 1.0) continue;

        return [
            'found'  => true,
            'rrn'    => (string)($tx['referenceNumber'] ?? $tx['transactionId'] ?? ''),
            'amount' => (string)($tx['amount'] ?? $amount),
        ];
    }

    // Pass 2: amount-only fallback (wrong mobile entered / device offline)
    // Pick the most recent successful transaction matching the amount
    if ($amount > 0) {
        $best = null; $bestTime = 0;
        foreach ($list as $tx) {
            if (!is_array($tx)) continue;
            if (strtolower((string)($tx['paymentStatus'] ?? '')) !== 'success') continue;
            $txTime = strtotime((string)($tx['transactionDate'] ?? ''));
            if ($txTime && $txTime < $cutoff) continue;
            if (abs((float)($tx['amount'] ?? 0) - $amount) > 1.0) continue;
            if ($txTime >= $bestTime) { $best = $tx; $bestTime = $txTime; }
        }
        if ($best !== null) {
            return [
                'found'  => true,
                'rrn'    => (string)($best['referenceNumber'] ?? $best['transactionId'] ?? ''),
                'amount' => (string)($best['amount'] ?? $amount),
            ];
        }
    }

    return ['found' => false, 'rrn' => '', 'amount' => ''];
}

// ── Routing ───────────────────────────────────────────────────────────────────
$action = trim($_GET['action'] ?? '');
$method = $_SERVER['REQUEST_METHOD'];

// GET ?action=fp_status
if ($action === 'fp_status') {
    $u = getSetting('fp_username');
    echo json_encode(['ok' => true, 'configured' => $u !== '']);
    exit;
}

// POST ?action=fp_login
if ($method === 'POST' && $action === 'fp_login') {
    purgeOldSessions();

    if (!function_exists('curl_init')) {
        echo json_encode(['ok' => false, 'error' => 'cURL not available on this server.']);
        exit;
    }

    $username      = getSetting('fp_username');
    $password      = getSetting('fp_password');

    if ($username === '' || $password === '') {
        echo json_encode(['ok' => false, 'error' => 'FonePay credentials not configured in admin portal.']);
        exit;
    }

    $token      = bin2hex(random_bytes(16));
    $cookieFile = DATA_DIR . '/fp_sess_' . $token . '.cookies';

    $res = fpCurl(FP_LOGIN_URL, 'POST', [
        'emailOrUsername' => $username,
        'password'        => $password,
        'clientCode'      => FP_CLIENT_CODE,
        'corporateCode'   => FP_CORPORATE_CODE,
    ], $cookieFile);

    if ($res['code'] === 0) {
        echo json_encode(['ok' => false, 'error' => 'Could not reach FonePay: ' . $res['error']]);
        exit;
    }

    $body = json_decode($res['body'], true);

    // Detect login failure
    if ($res['code'] >= 400) {
        $msg = (is_array($body) && isset($body['message'])) ? $body['message'] : 'Login failed (HTTP ' . $res['code'] . ')';
        echo json_encode(['ok' => false, 'error' => $msg]);
        exit;
    }

    if (!is_array($body) || empty($body['isSuccess'])) {
        $msg = (is_array($body) && isset($body['message'])) ? $body['message'] : 'Login rejected by FonePay.';
        echo json_encode(['ok' => false, 'error' => $msg]);
        exit;
    }

    // merchantId is hardcoded — comes from login response or constant fallback
    $merchantId = (string)(
        $body['data']['merchantId'] ?? $body['merchantId'] ?? FP_MERCHANT_ID
    );

    writeSession($token, ['merchantId' => $merchantId, 'created' => time()]);
    echo json_encode(['ok' => true, 'session_token' => $token]);
    exit;
}

// POST ?action=fp_get_txns
if ($method === 'POST' && $action === 'fp_get_txns') {
    $input  = json_decode((string)file_get_contents('php://input'), true) ?? [];
    $stoken = trim((string)($input['session_token'] ?? ''));
    $mobile = preg_replace('/\D/', '', (string)($input['mobile'] ?? ''));
    $amount = (float)($input['amount'] ?? 0);

    if ($stoken === '' || $mobile === '') {
        echo json_encode(['ok' => false, 'error' => 'session_token and mobile required']);
        exit;
    }

    $sess = readSession($stoken);
    if (empty($sess)) {
        echo json_encode(['ok' => false, 'error' => 'session_expired']);
        exit;
    }

    $merchantId = $sess['merchantId'] ?? FP_MERCHANT_ID;
    $cookieFile = DATA_DIR . '/fp_sess_' . $stoken . '.cookies';
    $today      = date('Y-m-d');

    $url = FP_TXN_URL . '?' . http_build_query([
        'page'                    => 0,
        'size'                    => 100,
        'fromTransmissionDateTime'=> $today,
        'toTransmissionDateTime'  => $today,
    ]);

    $res = fpCurl($url, 'POST', ['merchantId' => (int)$merchantId], $cookieFile);

    // Clean up session
    @unlink(DATA_DIR . '/fp_sess_' . $stoken . '.json');
    @unlink($cookieFile);

    if ($res['code'] === 0) {
        echo json_encode(['ok' => false, 'error' => 'Could not reach FonePay transactions API: ' . $res['error']]);
        exit;
    }

    $body = json_decode($res['body'], true);

    if (!is_array($body) || empty($body['isSuccess'])) {
        $msg = (is_array($body) && isset($body['message'])) ? $body['message'] : 'Transactions API error (HTTP ' . $res['code'] . ')';
        echo json_encode(['ok' => false, 'error' => $msg]);
        exit;
    }

    // Response: { data: { content: [...] } }
    $txList = [];
    if (isset($body['data']['content']) && is_array($body['data']['content'])) {
        $txList = $body['data']['content'];
    }

    $result = findInTransactions($txList, $mobile, $amount);

    if ($result['found']) {
        saveVerifiedPayment($mobile, $result['amount'], $result['rrn']);
    }

    echo json_encode([
        'ok'     => true,
        'found'  => $result['found'],
        'rrn'    => $result['rrn'],
        'amount' => $result['amount'],
    ]);
    exit;
}

http_response_code(400);
echo json_encode(['ok' => false, 'error' => 'Unknown action']);
