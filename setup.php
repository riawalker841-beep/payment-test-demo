<?php
/**
 * setup.php — One-time health check for PayGate
 *
 * Visit this URL after uploading to verify everything is working.
 * Safe to leave on the server — it only reads, never modifies.
 * Delete it once you've confirmed setup is OK.
 */

$checks = [];

// 1. PHP version
$phpOk = version_compare(PHP_VERSION, '7.4.0', '>=');
$checks[] = [
    'label'  => 'PHP version (' . PHP_VERSION . ')',
    'ok'     => $phpOk,
    'detail' => $phpOk ? 'Good' : 'Requires PHP 7.4 or newer',
];

// 2. PDO SQLite extension
$sqliteOk = extension_loaded('pdo_sqlite');
$checks[] = [
    'label'  => 'PDO SQLite extension',
    'ok'     => $sqliteOk,
    'detail' => $sqliteOk ? 'Loaded' : 'pdo_sqlite is not available — contact your host',
];

// 3. data/ directory exists and is writable
$dataDir  = __DIR__ . '/data';
$dirOk    = is_dir($dataDir);
if (!$dirOk) {
    $dirOk = @mkdir($dataDir, 0755, true);
}
$writeOk = $dirOk && is_writable($dataDir);
$checks[] = [
    'label'  => 'data/ directory writable',
    'ok'     => $writeOk,
    'detail' => $writeOk
        ? realpath($dataDir)
        : 'Cannot write to data/ — run: chmod 755 data/',
];

// 4. Can create / open the SQLite database
$dbOk     = false;
$dbDetail = '';
if ($sqliteOk && $writeOk) {
    $dbFile = $dataDir . '/payments.db';
    try {
        $db = new PDO('sqlite:' . $dbFile, null, null, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        ]);
        $db->exec('CREATE TABLE IF NOT EXISTS _test (id INTEGER)');
        $db->exec('DROP TABLE _test');
        $dbOk     = true;
        $dbDetail = $dbFile;
    } catch (Throwable $e) {
        $dbDetail = $e->getMessage();
    }
}
$checks[] = [
    'label'  => 'SQLite database',
    'ok'     => $dbOk,
    'detail' => $dbDetail,
];

// 5. webhook.php is reachable
$webhookFile = __FILE__ !== __DIR__ . '/webhook.php' ? __DIR__ . '/webhook.php' : __FILE__;
$webhookOk   = file_exists(__DIR__ . '/webhook.php');
$checks[] = [
    'label'  => 'webhook.php present',
    'ok'     => $webhookOk,
    'detail' => $webhookOk ? __DIR__ . '/webhook.php' : 'File not found',
];

$allOk   = array_reduce($checks, fn($c, $i) => $c && $i['ok'], true);
$baseUrl = (isset($_SERVER['HTTPS']) ? 'https' : 'http')
         . '://' . $_SERVER['HTTP_HOST']
         . rtrim(dirname($_SERVER['REQUEST_URI']), '/');

?><!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PayGate Setup Check</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
       background:#0f172a;color:#f8fafc;min-height:100vh;
       display:flex;align-items:center;justify-content:center;padding:1.5rem}
  .card{background:#1e293b;border-radius:16px;padding:2rem;width:100%;max-width:560px}
  h1{font-size:1.3rem;margin-bottom:.25rem}
  .sub{color:#94a3b8;font-size:.85rem;margin-bottom:1.5rem}
  .check{display:flex;align-items:flex-start;gap:.75rem;
         padding:.65rem .75rem;border-radius:10px;margin-bottom:.5rem;background:#0f172a}
  .icon{font-size:1.1rem;flex-shrink:0;margin-top:.05rem}
  .label{font-size:.9rem;font-weight:600}
  .detail{font-size:.75rem;color:#94a3b8;margin-top:.15rem;word-break:break-all}
  .ok .label{color:#4ade80}
  .fail .label{color:#f87171}
  .banner{margin-top:1.25rem;padding:1rem;border-radius:12px;text-align:center;
          font-size:.95rem;font-weight:600}
  .banner.ok{background:#14532d;color:#4ade80}
  .banner.fail{background:#450a0a;color:#f87171}
  .links{margin-top:1.25rem;display:flex;flex-direction:column;gap:.5rem}
  .links a{display:block;background:#2563eb;color:#fff;text-align:center;
            padding:.7rem;border-radius:9px;text-decoration:none;font-size:.9rem;font-weight:600}
  .links a:hover{background:#1d4ed8}
  .links a.ghost{background:#334155;color:#f8fafc}
  .links a.ghost:hover{background:#475569}
  code{background:#0f172a;padding:.1rem .35rem;border-radius:5px;font-size:.8rem}
</style>
</head>
<body>
<div class="card">
  <h1>PayGate Setup Check</h1>
  <p class="sub">Verifying your server is ready to run PayGate</p>

  <?php foreach ($checks as $c): ?>
  <div class="check <?= $c['ok'] ? 'ok' : 'fail' ?>">
    <span class="icon"><?= $c['ok'] ? '✅' : '❌' ?></span>
    <div>
      <div class="label"><?= htmlspecialchars($c['label']) ?></div>
      <div class="detail"><?= htmlspecialchars($c['detail']) ?></div>
    </div>
  </div>
  <?php endforeach ?>

  <?php if ($allOk): ?>
  <div class="banner ok">Everything is set up correctly — PayGate is ready!</div>
  <div class="links">
    <a href="index.html">Open Customer Payment Page</a>
    <a href="admin.html">Open Admin Dashboard</a>
    <a href="webhook.php" class="ghost">Test Webhook endpoint (GET)</a>
  </div>
  <p style="margin-top:1rem;font-size:.78rem;color:#64748b;text-align:center">
    Webhook URL to enter in the Android PayChecker app:<br>
    <code><?= htmlspecialchars($baseUrl) ?>/webhook.php</code>
  </p>
  <?php else: ?>
  <div class="banner fail">Fix the issues above, then refresh this page.</div>
  <div class="links">
    <a href="setup.php" class="ghost">Recheck</a>
  </div>
  <?php endif ?>
</div>
</body>
</html>
