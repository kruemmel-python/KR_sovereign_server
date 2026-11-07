<?php
declare(strict_types=1);

header('Content-Type: text/html; charset=UTF-8');
header('X-Robots-Tag: noindex, nofollow, noarchive');

session_start();

function escape(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function redirectHome(): never
{
    header('Location: /', true, 303);
    exit;
}

$requiredExtensions = ['pdo', 'pdo_mysql', 'mbstring', 'openssl', 'sodium'];
$missingExtensions = array_values(array_filter(
    $requiredExtensions,
    static fn(string $extension): bool => !extension_loaded($extension)
));

$csrfToken = $_SESSION['csrf_token'] ?? null;
if (!is_string($csrfToken) || strlen($csrfToken) !== 64) {
    $csrfToken = bin2hex(random_bytes(32));
    $_SESSION['csrf_token'] = $csrfToken;
}

$databaseVariables = [
    'host' => getenv('SOVEREIGN_CMS_DB_HOST'),
    'port' => getenv('SOVEREIGN_CMS_DB_PORT'),
    'name' => getenv('SOVEREIGN_CMS_DB_NAME'),
    'user' => getenv('SOVEREIGN_CMS_DB_USER'),
    'password' => getenv('SOVEREIGN_CMS_DB_PASSWORD'),
];
$databaseConfigured = $missingExtensions === [] && array_reduce(
    $databaseVariables,
    static fn(bool $ready, mixed $value): bool => $ready && is_string($value) && $value !== '',
    true
);

$pdo = null;
$databaseOnline = false;
$notice = null;
$error = null;
$notes = [];

if ($databaseConfigured) {
    try {
        $dsn = sprintf(
            'mysql:host=%s;port=%s;dbname=%s;charset=utf8mb4',
            $databaseVariables['host'],
            $databaseVariables['port'],
            $databaseVariables['name']
        );
        $pdo = new PDO($dsn, $databaseVariables['user'], $databaseVariables['password'], [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
            PDO::ATTR_PERSISTENT => false,
        ]);
        $pdo->exec(
            'CREATE TABLE IF NOT EXISTS sovereign_notes (' .
            'id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,' .
            'message VARCHAR(200) NOT NULL,' .
            'created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP' .
            ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci'
        );
        $databaseOnline = true;
    } catch (Throwable $exception) {
        error_log('Sovereign demo database connection failed: ' . $exception->getMessage());
        $error = 'MariaDB ist momentan nicht erreichbar. Starte MariaDB im Control Center.';
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $submittedToken = $_POST['csrf_token'] ?? '';
    if (!is_string($submittedToken) || !hash_equals($csrfToken, $submittedToken)) {
        http_response_code(403);
        $error = 'Die Sicherheitsprüfung der Anfrage ist fehlgeschlagen.';
    } elseif (!$databaseOnline || !$pdo instanceof PDO) {
        http_response_code(503);
        $error = 'Die Datenbank ist nicht verfügbar.';
    } else {
        $action = $_POST['action'] ?? '';
        if ($action === 'add') {
            $message = trim((string)($_POST['message'] ?? ''));
            if ($message === '' || mb_strlen($message, 'UTF-8') > 200) {
                $error = 'Bitte gib einen Text mit höchstens 200 Zeichen ein.';
            } else {
                $statement = $pdo->prepare('INSERT INTO sovereign_notes (message) VALUES (:message)');
                $statement->execute(['message' => $message]);
                $_SESSION['flash'] = 'Notiz gespeichert.';
                redirectHome();
            }
        } elseif ($action === 'delete') {
            $id = filter_var($_POST['id'] ?? null, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);
            if ($id === false) {
                $error = 'Ungültige Notiz-ID.';
            } else {
                $statement = $pdo->prepare('DELETE FROM sovereign_notes WHERE id = :id');
                $statement->execute(['id' => $id]);
                $_SESSION['flash'] = 'Notiz gelöscht.';
                redirectHome();
            }
        } else {
            http_response_code(400);
            $error = 'Unbekannte Aktion.';
        }
    }
}

if ($databaseOnline && $pdo instanceof PDO) {
    $notes = $pdo->query(
        'SELECT id, message, created_at FROM sovereign_notes ORDER BY id DESC LIMIT 50'
    )->fetchAll();
}

$flash = $_SESSION['flash'] ?? null;
unset($_SESSION['flash']);
if (is_string($flash)) {
    $notice = $flash;
}

$phpReady = $missingExtensions === [];
?>
<!doctype html>
<html lang="de">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Sovereign Notizen</title>
  <style>
    :root { color-scheme: dark; font-family: Inter, system-ui, sans-serif; background: #07111f; color: #e5eefb; }
    * { box-sizing: border-box; }
    body { margin: 0; min-height: 100vh; background: radial-gradient(circle at top, #12345a, #07111f 55%); }
    main { width: min(880px, calc(100% - 32px)); margin: 48px auto; }
    header, section { background: rgba(15, 31, 52, .94); border: 1px solid #284866; border-radius: 18px; padding: 24px; margin-bottom: 18px; box-shadow: 0 18px 50px #0007; }
    h1 { margin: 0 0 8px; color: #55c7ff; font-size: clamp(2rem, 5vw, 3.3rem); }
    h2 { margin-top: 0; }
    .status { display: flex; gap: 10px; flex-wrap: wrap; margin-top: 18px; }
    .badge { border-radius: 999px; padding: 7px 12px; background: #253a52; }
    .ok { background: #0f5132; color: #b9ffd9; }
    .off { background: #6b2631; color: #ffd8de; }
    form.add { display: grid; grid-template-columns: 1fr auto; gap: 10px; }
    input[type=text] { width: 100%; border: 1px solid #416787; border-radius: 10px; padding: 13px; background: #091827; color: #fff; font: inherit; }
    button { border: 1px solid #58c9ff; border-radius: 10px; padding: 11px 16px; background: #0674ad; color: #fff; font-weight: 700; cursor: pointer; }
    button.delete { background: #84283a; border-color: #ff7891; }
    ul { list-style: none; padding: 0; margin: 18px 0 0; }
    li { display: grid; grid-template-columns: 1fr auto; gap: 15px; align-items: center; padding: 14px 0; border-top: 1px solid #28445f; }
    small { display: block; color: #91a8bd; margin-top: 5px; }
    .message { border-radius: 10px; padding: 12px 14px; margin-bottom: 18px; }
    .success { background: #103f2c; color: #c4ffdd; }
    .error { background: #5b202b; color: #ffdce2; }
    .empty { color: #91a8bd; }
    @media (max-width: 620px) { form.add { grid-template-columns: 1fr; } main { margin-top: 20px; } }
  </style>
</head>
<body>
<main>
  <header>
    <h1>Sovereign Notizen</h1>
    <p>Eine kleine PHP-Seite mit sicherer MariaDB-Anbindung.</p>
    <div class="status">
      <span class="badge <?= $phpReady ? 'ok' : 'off' ?>">PHP ist aktiv<?= $phpReady ? '' : ' – Erweiterungen fehlen' ?></span>
      <span class="badge <?= $databaseOnline ? 'ok' : 'off' ?>">MariaDB <?= $databaseOnline ? 'verbunden' : 'offline' ?></span>
    </div>
  </header>

  <section>
    <h2>Notiz hinzufügen</h2>
    <?php if ($notice !== null): ?><p class="message success"><?= escape($notice) ?></p><?php endif; ?>
    <?php if ($error !== null): ?><p class="message error"><?= escape($error) ?></p><?php endif; ?>
    <?php if ($missingExtensions !== []): ?>
      <p class="message error">Fehlende PHP-Erweiterungen: <?= escape(implode(', ', $missingExtensions)) ?></p>
    <?php elseif (!$databaseConfigured): ?>
      <p class="message error">Die CMS-Datenbank wurde noch nicht für PHP bereitgestellt.</p>
    <?php endif; ?>
    <form class="add" method="post" action="/">
      <input type="hidden" name="csrf_token" value="<?= escape($csrfToken) ?>">
      <input type="hidden" name="action" value="add">
      <input type="text" name="message" maxlength="200" required autocomplete="off" placeholder="Deine Notiz …" <?= $databaseOnline ? '' : 'disabled' ?>>
      <button type="submit" <?= $databaseOnline ? '' : 'disabled' ?>>Speichern</button>
    </form>
  </section>

  <section>
    <h2>Gespeicherte Notizen</h2>
    <?php if ($notes === []): ?>
      <p class="empty">Noch keine Notizen vorhanden.</p>
    <?php else: ?>
      <ul>
        <?php foreach ($notes as $note): ?>
          <li>
            <div><?= escape((string)$note['message']) ?><small><?= escape((string)$note['created_at']) ?></small></div>
            <form method="post" action="/">
              <input type="hidden" name="csrf_token" value="<?= escape($csrfToken) ?>">
              <input type="hidden" name="action" value="delete">
              <input type="hidden" name="id" value="<?= (int)$note['id'] ?>">
              <button class="delete" type="submit">Löschen</button>
            </form>
          </li>
        <?php endforeach; ?>
      </ul>
    <?php endif; ?>
  </section>
</main>
</body>
</html>
