<?php
declare(strict_types=1);

session_start();

mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);

// --- DB config (XAMPP defaults) ---
$DB_HOST = 'localhost';
$DB_USER = 'root';
$DB_PASS = '';
$DB_NAME = 'bet';

$flash = [];
$schemaWarnings = [];

function h(?string $v): string
{
    return htmlspecialchars($v ?? '', ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function add_flash(array &$flash, string $type, string $msg): void
{
    $flash[] = ['type' => $type, 'msg' => $msg];
}

function redirect_self(): never
{
    header('Location: ' . strtok($_SERVER['REQUEST_URI'] ?? '/', '?'));
    exit;
}

function csrf_token(): string
{
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
    return (string)$_SESSION['csrf'];
}

function require_csrf_or_throw(): void
{
    $sent = $_POST['csrf'] ?? '';
    $sess = $_SESSION['csrf'] ?? '';
    if (!is_string($sent) || !is_string($sess) || $sent === '' || !hash_equals($sess, $sent)) {
        throw new RuntimeException('Invalid CSRF token. Refresh the page and try again.');
    }
}

function current_user_name(): ?string
{
    return isset($_SESSION['user']['nome']) && is_string($_SESSION['user']['nome']) ? $_SESSION['user']['nome'] : null;
}

function is_admin(): bool
{
    return !empty($_SESSION['user']['is_admin']);
}

function column_exists(mysqli $db, string $table, string $column): bool
{
    $sql = "SELECT 1
            FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA = DATABASE()
              AND TABLE_NAME = ?
              AND COLUMN_NAME = ?
            LIMIT 1";
    $stmt = $db->prepare($sql);
    $stmt->bind_param('ss', $table, $column);
    $stmt->execute();
    $res = $stmt->get_result();
    return (bool)$res->fetch_row();
}

function column_meta(mysqli $db, string $table, string $column): ?array
{
    $sql = "SELECT IS_NULLABLE, COLUMN_DEFAULT, EXTRA
            FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA = DATABASE()
              AND TABLE_NAME = ?
              AND COLUMN_NAME = ?
            LIMIT 1";
    $stmt = $db->prepare($sql);
    $stmt->bind_param('ss', $table, $column);
    $stmt->execute();
    $row = $stmt->get_result()->fetch_assoc();
    if (!$row) {
        return null;
    }
    return [
        'is_nullable' => ((string)($row['IS_NULLABLE'] ?? 'NO')) === 'YES',
        'has_default' => array_key_exists('COLUMN_DEFAULT', $row) && $row['COLUMN_DEFAULT'] !== null,
        'extra' => (string)($row['EXTRA'] ?? ''),
    ];
}

function column_is_nullable(mysqli $db, string $table, string $column): bool
{
    $m = column_meta($db, $table, $column);
    return (bool)($m['is_nullable'] ?? false);
}

function column_is_auto_increment(mysqli $db, string $table, string $column): bool
{
    $m = column_meta($db, $table, $column);
    $extra = strtolower((string)($m['extra'] ?? ''));
    return str_contains($extra, 'auto_increment');
}

function ensure_schema(mysqli $db, array &$schemaWarnings): void
{
    // Wagers table (puntata): stores user wagers on a scommessa.
    try {
        $db->query(
            "CREATE TABLE IF NOT EXISTS puntata (
                id INT UNSIGNED NOT NULL AUTO_INCREMENT,
                giocatore_nome VARCHAR(255) NOT NULL,
                scommessa_nome VARCHAR(255) NOT NULL,
                scommessa_data_apertura DATETIME NULL,
                scelta ENUM('V','P') NOT NULL,
                importo DECIMAL(12,2) NOT NULL,
                quota DECIMAL(12,4) NOT NULL,
                stato ENUM('PENDING','WIN','LOSE','VOID') NOT NULL DEFAULT 'PENDING',
                payout DECIMAL(12,2) NOT NULL DEFAULT 0,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                settled_at DATETIME NULL,
                PRIMARY KEY (id),
                KEY idx_giocatore (giocatore_nome),
                KEY idx_scommessa (scommessa_nome, scommessa_data_apertura),
                KEY idx_stato (stato)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
        );
    } catch (Throwable $e) {
        $schemaWarnings[] = "Could not create `puntata` table: " . $e->getMessage();
    }

    // Some dumps define `puntata.id` without AUTO_INCREMENT. Try to normalize it.
    if (column_exists($db, 'puntata', 'id') && !column_is_auto_increment($db, 'puntata', 'id')) {
        try {
            $db->query("ALTER TABLE puntata MODIFY COLUMN id INT UNSIGNED NOT NULL AUTO_INCREMENT");
        } catch (Throwable $e) {
            $schemaWarnings[] = "Could not set `puntata.id` to AUTO_INCREMENT automatically: " . $e->getMessage();
        }
    }

    // Add Esito column to scommessa if missing (admin can edit it).
    // If you already have an `esito` column with a different case/name, adjust here.
    if (!column_exists($db, 'scommessa', 'Esito') && !column_exists($db, 'scommessa', 'esito')) {
        try {
            $db->query(
                "ALTER TABLE scommessa
                 ADD COLUMN Esito ENUM('APERTO','VINCITA','PERDITA','ANNULLATA') NOT NULL DEFAULT 'APERTO'"
            );
        } catch (Throwable $e) {
            $schemaWarnings[] = "Could not add `scommessa.Esito` automatically: " . $e->getMessage();
        }
    }

    // Add Puntata column to scommessa if missing (description/label of the bet).
    if (!column_exists($db, 'scommessa', 'Puntata') && !column_exists($db, 'scommessa', 'puntata')) {
        try {
            $db->query(
                "ALTER TABLE scommessa
                 ADD COLUMN Puntata TEXT NULL"
            );
        } catch (Throwable $e) {
            $schemaWarnings[] = "Could not add `scommessa.Puntata` automatically: " . $e->getMessage();
        }
    }
}

function verify_password(string $input, string $stored): bool
{
    $stored = trim($stored);
    $input = (string)$input;
    // If stored looks like a bcrypt/argon hash, use password_verify.
    if (str_starts_with($stored, '$2y$') || str_starts_with($stored, '$argon2')) {
        return password_verify($input, $stored);
    }
    return hash_equals($stored, $input);
}

function bet_is_open(array $row, bool $hasEsito): bool
{
    $dc = $row['Data_Chiusura'] ?? null;
    $closeAt = null;
    if ($dc !== null && $dc !== '') {
        try {
            $closeAt = new DateTime((string)$dc);
        } catch (Throwable) {
            $closeAt = null;
        }
    }

    // If Data_Chiusura is in the past, the bet is finished for wagering (even if Esito is still APERTO).
    if ($closeAt instanceof DateTime) {
        if ($closeAt <= new DateTime('now')) {
            return false;
        }
    }

    if ($hasEsito) {
        $esito = (string)($row['Esito'] ?? 'APERTO');
        if ($esito === '') {
            $esito = 'APERTO';
        }
        return ($esito === 'APERTO');
    }
    // Fallback if Esito column does not exist: treat as open if Data_Chiusura is null or in the future.
    $dc = $row['Data_Chiusura'] ?? null;
    if ($dc === null || $dc === '') {
        return true;
    }
    try {
        $closeAt = new DateTime((string)$dc);
        return $closeAt > new DateTime('now');
    } catch (Throwable) {
        return false;
    }
}

function bet_status_label(array $row, bool $hasEsito): string
{
    $dc = $row['Data_Chiusura'] ?? null;
    $closeAt = null;
    if ($dc !== null && $dc !== '') {
        try {
            $closeAt = new DateTime((string)$dc);
        } catch (Throwable) {
            $closeAt = null;
        }
    }

    if ($hasEsito) {
        $esito = (string)($row['Esito'] ?? 'APERTO');
        if ($esito === '') {
            $esito = 'APERTO';
        }
        if ($esito !== 'APERTO') {
            return $esito;
        }
        if ($closeAt instanceof DateTime && $closeAt <= new DateTime('now')) {
            return 'SCADUTA';
        }
        return 'APERTO';
    }

    if ($closeAt instanceof DateTime && $closeAt <= new DateTime('now')) {
        return 'SCADUTA';
    }
    return 'APERTO';
}

function settle_pending_wagers(
    mysqli $db,
    string $scommessaNome,
    string $scommessaDataApertura,
    string $esito
): int {
    $stmt = $db->prepare(
        "SELECT id, giocatore_nome, scelta, importo, quota
         FROM puntata
         WHERE scommessa_nome = ?
           AND scommessa_data_apertura = ?
           AND stato = 'PENDING'
         FOR UPDATE"
    );
    $stmt->bind_param('ss', $scommessaNome, $scommessaDataApertura);
    $stmt->execute();
    $wagers = $stmt->get_result();

    $settled = 0;
    while ($w = $wagers->fetch_assoc()) {
        $id = (int)$w['id'];
        $giocatore = (string)$w['giocatore_nome'];
        $sc = (string)$w['scelta'];
        $importo = (float)$w['importo'];
        $quota = isset($w['quota']) ? (float)$w['quota'] : 0.0;

        $newState = 'LOSE';
        $payout = 0.0;

        if ($esito === 'ANNULLATA') {
            $newState = 'VOID';
            $payout = $importo;
        } elseif ($esito === 'VINCITA') {
            if ($sc === 'V') {
                $newState = 'WIN';
                $payout = round($importo * $quota, 2);
            }
        } elseif ($esito === 'PERDITA') {
            if ($sc === 'P') {
                $newState = 'WIN';
                $payout = round($importo * $quota, 2);
            }
        }

        if ($payout > 0) {
            $stmt2 = $db->prepare("UPDATE giocatore SET Saldo = Saldo + ? WHERE Nome = ?");
            $stmt2->bind_param('ds', $payout, $giocatore);
            $stmt2->execute();
        }

        $stmt2 = $db->prepare("UPDATE puntata SET stato = ?, payout = ?, settled_at = NOW() WHERE id = ?");
        $stmt2->bind_param('sdi', $newState, $payout, $id);
        $stmt2->execute();
        $settled++;
    }

    return $settled;
}

function bet_key_fields(array $row): array
{
    // We do NOT rely on a non-existent `id` column.
    // Use (Nome, Data_Apertura) as a stable identifier.
    return [(string)($row['Nome'] ?? ''), (string)($row['Data_Apertura'] ?? '')];
}

// --- Connect ---
try {
    $db = new mysqli($DB_HOST, $DB_USER, $DB_PASS, $DB_NAME);
    $db->set_charset('utf8mb4');
} catch (Throwable $e) {
    http_response_code(500);
    echo "<h1>DB connection failed</h1><pre>" . h($e->getMessage()) . "</pre>";
    exit;
}

ensure_schema($db, $schemaWarnings);
$esitoCol = null;
if (column_exists($db, 'scommessa', 'Esito')) {
    $esitoCol = 'Esito';
} elseif (column_exists($db, 'scommessa', 'esito')) {
    $esitoCol = 'esito';
}
$hasEsito = $esitoCol !== null;
$esitoSelectSql = null;
if ($hasEsito) {
    // Some DB dumps store empty string instead of APERTO.
    $esitoSelectSql = "COALESCE(NULLIF({$esitoCol}, ''), 'APERTO') AS Esito";
}

$puntataSelectSql = null;
if (column_exists($db, 'scommessa', 'Puntata')) {
    $puntataSelectSql = 'Puntata';
} elseif (column_exists($db, 'scommessa', 'puntata')) {
    $puntataSelectSql = 'puntata AS Puntata';
} else {
    $puntataSelectSql = "'' AS Puntata";
}

$puntataIdAuto = column_exists($db, 'puntata', 'id') && column_is_auto_increment($db, 'puntata', 'id');
$puntataSettledAtNullable = column_exists($db, 'puntata', 'settled_at') && column_is_nullable($db, 'puntata', 'settled_at');

// --- Actions ---
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
if ($method === 'POST') {
    $action = $_POST['action'] ?? '';
    try {
        require_csrf_or_throw();

        if ($action === 'login') {
            $nome = trim((string)($_POST['nome'] ?? ''));
            $password = (string)($_POST['password'] ?? '');

            if ($nome === '' || $password === '') {
                throw new RuntimeException('Insert username and password.');
            }

            $stmt = $db->prepare("SELECT Nome, Password FROM giocatore WHERE Nome = ? LIMIT 1");
            $stmt->bind_param('s', $nome);
            $stmt->execute();
            $user = $stmt->get_result()->fetch_assoc();
            if (!$user) {
                throw new RuntimeException('Invalid credentials.');
            }
            if (!verify_password($password, (string)$user['Password'])) {
                throw new RuntimeException('Invalid credentials.');
            }

            $_SESSION['user'] = [
                'nome' => (string)$user['Nome'],
                'is_admin' => ((string)$user['Nome'] === 'admin'),
            ];
            add_flash($flash, 'success', 'Logged in.');
            redirect_self();
        }

        if ($action === 'logout') {
            unset($_SESSION['user']);
            add_flash($flash, 'success', 'Logged out.');
            redirect_self();
        }

        if ($action === 'place_bet') {
            $nomeGiocatore = current_user_name();
            if ($nomeGiocatore === null) {
                throw new RuntimeException('Login required.');
            }
            if (is_admin()) {
                throw new RuntimeException('Admin cannot place wagers from this page.');
            }

            $scommessaNome = trim((string)($_POST['scommessa_nome'] ?? ''));
            $scommessaDataApertura = trim((string)($_POST['data_apertura'] ?? ''));
            $scelta = (string)($_POST['scelta'] ?? '');
            $importoRaw = (string)($_POST['importo'] ?? '0');

            if ($scommessaNome === '' || $scelta === '' || $scommessaDataApertura === '') {
                throw new RuntimeException('Invalid wager request.');
            }
            if ($scelta !== 'V' && $scelta !== 'P') {
                throw new RuntimeException('Invalid choice.');
            }
            $importo = (float)str_replace(',', '.', $importoRaw);
            if (!is_finite($importo) || $importo <= 0) {
                throw new RuntimeException('Importo must be > 0.');
            }

            $db->begin_transaction();
            try {
                $stmt = $db->prepare("SELECT Saldo FROM giocatore WHERE Nome = ? FOR UPDATE");
                $stmt->bind_param('s', $nomeGiocatore);
                $stmt->execute();
                $rowSaldo = $stmt->get_result()->fetch_assoc();
                if (!$rowSaldo) {
                    throw new RuntimeException('User not found.');
                }
                $saldo = (float)$rowSaldo['Saldo'];
                if ($importo > $saldo) {
                    throw new RuntimeException('Not enough credits.');
                }

                if ($hasEsito) {
                    $stmt = $db->prepare(
                        "SELECT Nome, Data_Apertura, Quota_Vincita, Quota_Perdita, {$esitoSelectSql}, Data_Chiusura
                          FROM scommessa
                          WHERE Nome = ? AND Data_Apertura = ?
                          LIMIT 1
                          FOR UPDATE"
                    );
                } else {
                    $stmt = $db->prepare(
                        "SELECT Nome, Data_Apertura, Quota_Vincita, Quota_Perdita, Data_Chiusura
                         FROM scommessa
                         WHERE Nome = ? AND Data_Apertura = ?
                         LIMIT 1
                         FOR UPDATE"
                    );
                }
                $stmt->bind_param('ss', $scommessaNome, $scommessaDataApertura);
                $stmt->execute();
                $scommessa = $stmt->get_result()->fetch_assoc();
                if (!$scommessa) {
                    throw new RuntimeException('Scommessa not found.');
                }
                if (!bet_is_open($scommessa, $hasEsito)) {
                    throw new RuntimeException('This scommessa is closed.');
                }

                $quota = $scelta === 'V' ? (float)$scommessa['Quota_Vincita'] : (float)$scommessa['Quota_Perdita'];
                if ($quota <= 0) {
                    throw new RuntimeException('Invalid quota.');
                }

                $potentialPayout = round($importo * $quota, 2);
                $stato = 'PENDING';
                $settledAtExpr = $puntataSettledAtNullable ? 'NULL' : 'NOW(6)';
                if ($puntataIdAuto) {
                    $stmt = $db->prepare(
                        "INSERT INTO puntata (giocatore_nome, scommessa_nome, scommessa_data_apertura, scelta, importo, quota, stato, payout, created_at, settled_at)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW(6), {$settledAtExpr})"
                    );
                    $stmt->bind_param('ssssddsd', $nomeGiocatore, $scommessaNome, $scommessaDataApertura, $scelta, $importo, $quota, $stato, $potentialPayout);
                    $stmt->execute();
                } else {
                    // Fallback for schemas where `puntata.id` is NOT AUTO_INCREMENT.
                    $stmt = $db->prepare("SELECT id FROM puntata ORDER BY id DESC LIMIT 1 FOR UPDATE");
                    $stmt->execute();
                    $last = $stmt->get_result()->fetch_assoc();
                    $nextId = $last ? ((int)$last['id'] + 1) : 1;

                    $stmt = $db->prepare(
                        "INSERT INTO puntata (id, giocatore_nome, scommessa_nome, scommessa_data_apertura, scelta, importo, quota, stato, payout, created_at, settled_at)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(6), {$settledAtExpr})"
                    );
                    $stmt->bind_param('issssddsd', $nextId, $nomeGiocatore, $scommessaNome, $scommessaDataApertura, $scelta, $importo, $quota, $stato, $potentialPayout);
                    $stmt->execute();
                }

                $stmt = $db->prepare("UPDATE giocatore SET Saldo = Saldo - ? WHERE Nome = ?");
                $stmt->bind_param('ds', $importo, $nomeGiocatore);
                $stmt->execute();

                $db->commit();
                add_flash($flash, 'success', 'Wager placed.');
                redirect_self();
            } catch (Throwable $e) {
                $db->rollback();
                throw $e;
            }
        }

        if ($action === 'set_esito') {
            if (!is_admin()) {
                throw new RuntimeException('Admin only.');
            }
            if (!$hasEsito) {
                throw new RuntimeException('`scommessa.Esito`/`scommessa.esito` column not available.');
            }
            $scommessaNome = trim((string)($_POST['scommessa_nome'] ?? ''));
            $scommessaDataApertura = trim((string)($_POST['data_apertura'] ?? ''));
            $esito = (string)($_POST['esito'] ?? '');
            $allowed = ['APERTO', 'VINCITA', 'PERDITA', 'ANNULLATA'];
            if ($scommessaNome === '' || $scommessaDataApertura === '' || !in_array($esito, $allowed, true)) {
                throw new RuntimeException('Invalid update.');
            }

            $db->begin_transaction();
            try {
                $stmt = $db->prepare(
                    "SELECT Nome, Data_Apertura, Quota_Vincita, Quota_Perdita, Data_Chiusura
                     FROM scommessa
                     WHERE Nome = ? AND Data_Apertura = ?
                     LIMIT 1
                     FOR UPDATE"
                );
                $stmt->bind_param('ss', $scommessaNome, $scommessaDataApertura);
                $stmt->execute();
                $scommessa = $stmt->get_result()->fetch_assoc();
                if (!$scommessa) {
                    throw new RuntimeException('Scommessa not found.');
                }

                $stmt = $db->prepare("UPDATE scommessa SET {$esitoCol} = ? WHERE Nome = ? AND Data_Apertura = ?");
                $stmt->bind_param('sss', $esito, $scommessaNome, $scommessaDataApertura);
                $stmt->execute();

                // Payout system: settle ONLY when the bet is finished (Data_Chiusura reached) and Esito is final.
                $settledCount = 0;
                if ($esito !== 'APERTO') {
                    $dc = $scommessa['Data_Chiusura'] ?? null;
                    $closeAt = null;
                    if ($dc !== null && $dc !== '') {
                        try {
                            $closeAt = new DateTime((string)$dc);
                        } catch (Throwable) {
                            $closeAt = null;
                        }
                    }

                    $canSettleNow = true;
                    if ($closeAt instanceof DateTime) {
                        $canSettleNow = ($closeAt <= new DateTime('now'));
                    }

                    if ($canSettleNow) {
                        $settledCount = settle_pending_wagers($db, $scommessaNome, $scommessaDataApertura, $esito);
                    }
                }

                $db->commit();
                if ($esito === 'APERTO') {
                    add_flash($flash, 'success', 'Esito updated.');
                } else {
                    if ($settledCount > 0) {
                        add_flash($flash, 'success', "Esito updated. Paid out {$settledCount} wager(s).");
                    } else {
                        add_flash($flash, 'success', 'Esito updated. No payouts yet (either no pending wagers, or Data_Chiusura not reached).');
                    }
                }
                redirect_self();
            } catch (Throwable $e) {
                $db->rollback();
                throw $e;
            }
        }

        if ($action === 'settle_bet') {
            if (!is_admin()) {
                throw new RuntimeException('Admin only.');
            }
            if (!$hasEsito) {
                throw new RuntimeException('`scommessa.Esito`/`scommessa.esito` column not available.');
            }
            $scommessaNome = trim((string)($_POST['scommessa_nome'] ?? ''));
            $scommessaDataApertura = trim((string)($_POST['data_apertura'] ?? ''));
            if ($scommessaNome === '' || $scommessaDataApertura === '') {
                throw new RuntimeException('Invalid settle request.');
            }

            $db->begin_transaction();
            try {
                $stmt = $db->prepare(
                    "SELECT Nome, Data_Apertura, Quota_Vincita, Quota_Perdita, Data_Chiusura, {$esitoSelectSql}
                     FROM scommessa
                     WHERE Nome = ? AND Data_Apertura = ?
                     LIMIT 1
                     FOR UPDATE"
                );
                $stmt->bind_param('ss', $scommessaNome, $scommessaDataApertura);
                $stmt->execute();
                $scommessa = $stmt->get_result()->fetch_assoc();
                if (!$scommessa) {
                    throw new RuntimeException('Scommessa not found.');
                }
                $esito = (string)($scommessa['Esito'] ?? 'APERTO');
                if ($esito === 'APERTO') {
                    throw new RuntimeException('This bet is still APERTO. Set Esito first.');
                }

                $dc = $scommessa['Data_Chiusura'] ?? null;
                if ($dc !== null && $dc !== '') {
                    try {
                        $closeAt = new DateTime((string)$dc);
                        if ($closeAt > new DateTime('now')) {
                            throw new RuntimeException('Cannot settle before Data_Chiusura.');
                        }
                    } catch (Throwable $e) {
                        if ($e instanceof RuntimeException) {
                            throw $e;
                        }
                        // If the date is invalid, allow manual settle.
                    }
                }

                $count = settle_pending_wagers($db, $scommessaNome, $scommessaDataApertura, $esito);

                $db->commit();
                add_flash($flash, 'success', "Settled {$count} pending wager(s).");
                redirect_self();
            } catch (Throwable $e) {
                $db->rollback();
                throw $e;
            }
        }

        throw new RuntimeException('Unknown action.');
    } catch (Throwable $e) {
        add_flash($flash, 'error', $e->getMessage());
    }
}

// --- Load view data ---
$userName = current_user_name();
$userRow = null;
if ($userName !== null) {
    $stmt = $db->prepare("SELECT Nome, Saldo, Email FROM giocatore WHERE Nome = ? LIMIT 1");
    $stmt->bind_param('s', $userName);
    $stmt->execute();
    $userRow = $stmt->get_result()->fetch_assoc();
}

if ($hasEsito) {
    $stmt = $db->prepare(
        "SELECT
            Nome,
            Data_Apertura,
            Quota_Vincita,
             Quota_Perdita,
             {$puntataSelectSql},
             Data_Chiusura,
            {$esitoSelectSql},
            (
                SELECT COUNT(*)
                FROM puntata p
                WHERE p.scommessa_nome = scommessa.Nome
                  AND p.scommessa_data_apertura = scommessa.Data_Apertura
                  AND p.stato = 'PENDING'
            ) AS pending_wagers
         FROM scommessa
         ORDER BY Data_Apertura DESC"
    );
} else {
    $stmt = $db->prepare(
        "SELECT Nome, Data_Apertura, Quota_Vincita, Quota_Perdita, {$puntataSelectSql}, Data_Chiusura
         FROM scommessa
         ORDER BY Data_Apertura DESC"
    );
}
$stmt->execute();
$bets = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);

// Remove bets that have been closed AND fully paid/refunded (no more PENDING wagers).
if ($hasEsito) {
    $bets = array_values(array_filter($bets, static function (array $b): bool {
        $esito = (string)($b['Esito'] ?? 'APERTO');
        if ($esito === 'APERTO') {
            return true;
        }
        $pending = isset($b['pending_wagers']) ? (int)$b['pending_wagers'] : 0;
        return $pending > 0;
    }));
}

$myWagers = [];
if ($userName !== null) {
    $stmt = $db->prepare(
        "SELECT scommessa_nome, scommessa_data_apertura, scelta, importo, quota, stato, payout, created_at, settled_at
         FROM puntata
         WHERE giocatore_nome = ?
           AND stato = 'PENDING'
         ORDER BY created_at DESC
         LIMIT 50"
    );
    $stmt->bind_param('s', $userName);
    $stmt->execute();
    $myWagers = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
}

$csrf = csrf_token();
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Bet</title>
    <style>
        :root { color-scheme: light; }
        body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 0; background: #0b1220; color: #e7eefc; }
        a { color: #9cc0ff; }
        .wrap { max-width: 1100px; margin: 0 auto; padding: 22px; }
        .card { background: #121b30; border: 1px solid #223055; border-radius: 12px; padding: 16px; }
        .row { display: grid; grid-template-columns: 1fr; gap: 14px; }
        @media (min-width: 980px) { .row { grid-template-columns: 1fr 1fr; } }
        h1 { font-size: 20px; margin: 0 0 12px; }
        h2 { font-size: 16px; margin: 0 0 10px; }
        .muted { color: #b7c6e6; }
        .flash { padding: 10px 12px; border-radius: 10px; margin: 10px 0; border: 1px solid transparent; }
        .flash.success { background: rgba(46, 204, 113, .10); border-color: rgba(46, 204, 113, .35); }
        .flash.error { background: rgba(231, 76, 60, .12); border-color: rgba(231, 76, 60, .35); }
        table { width: 100%; border-collapse: collapse; font-size: 13px; }
        th, td { padding: 8px 8px; border-bottom: 1px solid #223055; vertical-align: top; }
        th { text-align: left; color: #cfe0ff; font-weight: 600; }
        input, select, button { font: inherit; }
        input, select { width: 100%; padding: 8px 10px; border-radius: 10px; border: 1px solid #2a3a66; background: #0e1730; color: #e7eefc; }
        button { padding: 8px 12px; border-radius: 10px; border: 1px solid #2a3a66; background: #1a2a52; color: #e7eefc; cursor: pointer; }
        button:hover { background: #223566; }
        .inline { display: grid; grid-template-columns: 1fr 120px 160px 120px; gap: 8px; align-items: end; }
        .inline-admin { display: grid; grid-template-columns: 1fr 200px 120px 120px; gap: 8px; align-items: end; }
        .pill { display: inline-block; padding: 2px 8px; border-radius: 999px; border: 1px solid #2a3a66; color: #cfe0ff; font-size: 12px; }
        .pill.open { border-color: rgba(52, 152, 219, .55); }
        .pill.win { border-color: rgba(46, 204, 113, .55); }
        .pill.lose { border-color: rgba(231, 76, 60, .55); }
        .pill.void { border-color: rgba(241, 196, 15, .55); }
        .top { display:flex; justify-content: space-between; gap: 12px; align-items: center; margin-bottom: 14px; }
        .small { font-size: 12px; }
        .right { text-align: right; }
        .nowrap { white-space: nowrap; }
    </style>
</head>
<body>
<div class="wrap">
    <div class="top">
        <div>
            <h1>Bet</h1>
            <div class="muted small">DB: <span class="pill"><?= h($DB_NAME) ?></span></div>
        </div>
        <div class="right">
            <?php if ($userRow): ?>
                <div class="nowrap"><strong><?= h((string)$userRow['Nome']) ?></strong> <?= is_admin() ? '<span class="pill">admin</span>' : '<span class="pill">user</span>' ?></div>
                <div class="muted small">Saldo: <strong><?= h((string)$userRow['Saldo']) ?></strong></div>
                <form method="post" style="margin-top:8px;">
                    <input type="hidden" name="csrf" value="<?= h($csrf) ?>">
                    <input type="hidden" name="action" value="logout">
                    <button type="submit">Logout</button>
                </form>
            <?php else: ?>
                <span class="pill">not logged in</span>
            <?php endif; ?>
        </div>
    </div>

    <?php foreach ($schemaWarnings as $w): ?>
        <div class="flash error"><?= h($w) ?></div>
    <?php endforeach; ?>

    <?php foreach ($flash as $f): ?>
        <div class="flash <?= h($f['type']) ?>"><?= h($f['msg']) ?></div>
    <?php endforeach; ?>

    <div class="row">
        <div class="card">
            <h2>Login</h2>
            <?php if ($userRow): ?>
                <div class="muted">Already logged in.</div>
            <?php else: ?>
                <form method="post">
                    <input type="hidden" name="csrf" value="<?= h($csrf) ?>">
                    <input type="hidden" name="action" value="login">
                    <div style="display:grid; grid-template-columns: 1fr 1fr; gap: 10px;">
                        <div>
                            <div class="muted small">Nome</div>
                            <input name="nome" autocomplete="username" required>
                        </div>
                        <div>
                            <div class="muted small">Password</div>
                            <input name="password" type="password" autocomplete="current-password" required>
                        </div>
                    </div>
                    <div style="margin-top:10px;">
                        <button type="submit">Login</button>
                    </div>
                    <div class="muted small" style="margin-top:10px;">
                        Admin is detected by <code>Nome = admin</code>.
                    </div>
                </form>
            <?php endif; ?>
        </div>

        <div class="card">
            <h2>My pending wagers</h2>
            <?php if (!$userRow): ?>
                <div class="muted">Login to see your wagers.</div>
            <?php else: ?>
                <?php if (!$myWagers): ?>
                    <div class="muted">No wagers yet.</div>
                <?php else: ?>
                    <table>
                        <thead>
                        <tr>
                            <th>Scommessa</th>
                            <th class="nowrap">Apertura</th>
                            <th>Scelta</th>
                            <th class="nowrap">Importo</th>
                            <th class="nowrap">Quota</th>
                            <th>Stato</th>
                            <th class="nowrap">Payout</th>
                        </tr>
                        </thead>
                        <tbody>
                        <?php foreach ($myWagers as $w): ?>
                            <tr>
                                <td><?= h((string)$w['scommessa_nome']) ?></td>
                                <td class="nowrap"><?= h((string)$w['scommessa_data_apertura']) ?></td>
                                <td><?= $w['scelta'] === 'V' ? 'Vincita' : 'Perdita' ?></td>
                                <td class="nowrap"><?= h((string)$w['importo']) ?></td>
                                <td class="nowrap"><?= h((string)$w['quota']) ?></td>
                                <?php
                                $pill = 'open';
                                if ($w['stato'] === 'WIN') $pill = 'win';
                                if ($w['stato'] === 'LOSE') $pill = 'lose';
                                if ($w['stato'] === 'VOID') $pill = 'void';
                                ?>
                                <td><span class="pill <?= h($pill) ?>"><?= h((string)$w['stato']) ?></span></td>
                                <td class="nowrap"><?= h((string)$w['payout']) ?></td>
                            </tr>
                        <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php endif; ?>
            <?php endif; ?>
        </div>
    </div>

    <div class="card" style="margin-top:14px;">
        <h2>Scommesse</h2>
        <?php if (!$bets): ?>
            <div class="muted">No bets found in <code>scommessa</code>.</div>
        <?php else: ?>
            <table>
                <thead>
                <tr>
                    <th>Nome</th>
                    <th class="nowrap">Data apertura</th>
                    <th class="nowrap">Quota vincita</th>
                    <th class="nowrap">Quota perdita</th>
                    <th>Puntata (descr.)</th>
                    <th class="nowrap">Chiusura</th>
                    <th>Esito</th>
                    <th style="width: 360px;">Azioni</th>
                </tr>
                </thead>
                <tbody>
                <?php foreach ($bets as $b): ?>
                    <?php
                    [$betNome, $betApertura] = bet_key_fields($b);
                    $open = bet_is_open($b, $hasEsito);
                    $esitoLabel = bet_status_label($b, $hasEsito);
                    $pillClass = 'open';
                    if ($esitoLabel === 'VINCITA') $pillClass = 'win';
                    if ($esitoLabel === 'PERDITA') $pillClass = 'lose';
                    if ($esitoLabel === 'ANNULLATA') $pillClass = 'void';
                    if ($esitoLabel === 'SCADUTA') $pillClass = 'lose';
                    ?>
                    <tr>
                        <td><?= h($betNome) ?></td>
                        <td class="nowrap"><?= h($betApertura) ?></td>
                        <td class="nowrap"><?= h((string)$b['Quota_Vincita']) ?></td>
                        <td class="nowrap"><?= h((string)$b['Quota_Perdita']) ?></td>
                        <td><?= h((string)$b['Puntata']) ?></td>
                        <td class="nowrap"><?= h((string)($b['Data_Chiusura'] ?? '')) ?></td>
                        <td><span class="pill <?= h($pillClass) ?>"><?= h($esitoLabel) ?></span></td>
                        <td>
                            <?php if ($userRow && !is_admin() && $open): ?>
                                <form method="post" class="inline">
                                    <input type="hidden" name="csrf" value="<?= h($csrf) ?>">
                                    <input type="hidden" name="action" value="place_bet">
                                    <input type="hidden" name="scommessa_nome" value="<?= h($betNome) ?>">
                                    <input type="hidden" name="data_apertura" value="<?= h($betApertura) ?>">
                                    <div>
                                        <div class="muted small">Importo</div>
                                        <input name="importo" inputmode="decimal" placeholder="e.g. 10" required>
                                    </div>
                                    <div>
                                        <div class="muted small">Scelta</div>
                                        <select name="scelta" required>
                                            <option value="V">Vincita</option>
                                            <option value="P">Perdita</option>
                                        </select>
                                    </div>
                                    <div>
                                        <button type="submit">Punta</button>
                                    </div>
                                    <div class="muted small">Saldo: <?= h((string)$userRow['Saldo']) ?></div>
                                </form>
                            <?php elseif (is_admin()): ?>
                                <?php if (!$hasEsito): ?>
                                    <div class="muted small">No <code>Esito</code> column on <code>scommessa</code>.</div>
                                <?php else: ?>
                                    <form method="post" class="inline-admin">
                                        <input type="hidden" name="csrf" value="<?= h($csrf) ?>">
                                        <input type="hidden" name="scommessa_nome" value="<?= h($betNome) ?>">
                                        <input type="hidden" name="data_apertura" value="<?= h($betApertura) ?>">
                                        <div>
                                            <div class="muted small">Esito</div>
                                            <select name="esito" required>
                                                <?php foreach (['APERTO','VINCITA','PERDITA','ANNULLATA'] as $opt): ?>
                                                    <option value="<?= h($opt) ?>" <?= ($hasEsito && ($b['Esito'] ?? 'APERTO') === $opt) ? 'selected' : '' ?>><?= h($opt) ?></option>
                                                <?php endforeach; ?>
                                            </select>
                                        </div>
                                        <div>
                                            <button type="submit" name="action" value="set_esito">Aggiorna</button>
                                        </div>
                                        <div>
                                            <button type="submit" name="action" value="settle_bet" <?= (($b['Esito'] ?? 'APERTO') === 'APERTO') ? 'disabled' : '' ?>>Settle</button>
                                        </div>
                                    </form>
                                    <div class="muted small" style="margin-top:6px;">
                                        <?= (($b['Esito'] ?? 'APERTO') === 'APERTO')
                                            ? ($esitoLabel === 'SCADUTA' ? 'Scaduta: set Esito, then settle.' : 'Open')
                                            : 'Settles only PENDING wagers.' ?>
                                    </div>
                                <?php endif; ?>
                            <?php else: ?>
                                <div class="muted small"><?= $userRow ? ($open ? 'Login as user to bet.' : 'Finished.') : 'Login to bet.' ?></div>
                            <?php endif; ?>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
            <div class="muted small" style="margin-top:10px;">
                Note: This page identifies a bet by <code>(Nome, Data_Apertura)</code> and does not require an <code>id</code> column (fixes your “Unknown column 'id'” error).
            </div>
        <?php endif; ?>
    </div>
</div>
</body>
</html>
