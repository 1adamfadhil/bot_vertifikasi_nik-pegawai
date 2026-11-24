<?php
// Halaman ini khusus prototipe lokal. Jangan gunakan untuk kredensial perusahaan.
date_default_timezone_set('Asia/Jakarta');
session_name('telegram_dummy_verify');
session_set_cookie_params([
    'httponly' => true,
    'secure' => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'),
    'samesite' => 'Lax'
]);
session_start();
mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);

function h(string $value): string {
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}
function db(): mysqli {
    $conn = new mysqli('127.0.0.1', 'root', '', 'telegram_bot');
    $conn->set_charset('utf8mb4');
    return $conn;
}
function renderPage(string $title, string $body, int $status = 200): never {
    http_response_code($status);
    echo '<!doctype html><html lang="id"><head><meta charset="utf-8">';
    echo '<meta name="viewport" content="width=device-width, initial-scale=1">';
    echo '<title>' . h($title) . '</title><style>
    *{box-sizing:border-box}body{margin:0;background:#f3f6f8;color:#21313b;font:16px/1.5 Arial,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}
    .card{background:white;max-width:440px;width:100%;padding:28px;border:1px solid #dfe6eb;border-radius:16px;box-shadow:0 8px 28px rgba(20,40,50,.08)}
    h1{font-size:23px;margin:0 0 8px}.sub{color:#61717b;font-size:14px;margin:0 0 22px}.notice{padding:12px 14px;background:#eef5f8;border-radius:9px;margin:14px 0}label{display:block;font-weight:600;margin:15px 0 6px}input{width:100%;padding:12px;border:1px solid #bac8d0;border-radius:8px;font-size:16px}button{width:100%;border:0;background:#214151;color:white;font-size:16px;padding:13px;border-radius:8px;margin-top:20px;cursor:pointer}small{display:block;color:#687983;margin-top:18px}.error{background:#fff0f0;color:#922b2b}.success{background:#edf8ef;color:#236333}
    </style></head><body><main class="card">' . $body . '</main></body></html>';
    exit;
}

$token = trim((string)($_GET['token'] ?? $_POST['token'] ?? ''));
if (!preg_match('/^[a-f0-9]{64}$/', $token)) {
    renderPage('Link tidak valid', '<h1>Link verifikasi tidak valid</h1><div class="notice error">Buka kembali link terbaru yang dikirim oleh bot Telegram.</div>', 400);
}

$tokenHash = hash('sha256', $token);
$conn = null;
try {
    $conn = db();
    $stmt = $conn->prepare('SELECT * FROM telegram_verification_requests WHERE token_hash = ? LIMIT 1');
    $stmt->bind_param('s', $tokenHash);
    $stmt->execute();
    $request = $stmt->get_result()->fetch_assoc();
    $stmt->close();
} catch (Throwable $e) {
    error_log('Dummy verification DB error code: ' . $e->getCode());
    renderPage('Gangguan sistem', '<h1>Halaman sedang bermasalah</h1><div class="notice error">Database lokal belum siap. Pastikan MySQL Laragon aktif dan setup verifikasi sudah dijalankan.</div>', 500);
} finally {
    if ($conn instanceof mysqli) $conn->close();
}

if (!$request) {
    renderPage('Link tidak ditemukan', '<h1>Link verifikasi tidak ditemukan</h1><div class="notice error">Minta bot mengirimkan link verifikasi baru.</div>', 404);
}
if ($request['status'] !== 'pending') {
    $message = $request['status'] === 'verified'
        ? 'NIK pada permintaan ini sudah berhasil diverifikasi. Periksa chat Telegram untuk hasilnya.'
        : 'Permintaan verifikasi ini sudah tidak aktif. Silakan mulai ulang dari bot jika diperlukan.';
    renderPage('Permintaan tidak aktif', '<h1>Permintaan tidak aktif</h1><div class="notice">' . h($message) . '</div>');
}
if (strtotime($request['expires_at']) < time()) {
    $conn = db();
    $stmt = $conn->prepare("UPDATE telegram_verification_requests SET status='expired', notification_code='verification_expired', notification_sent_at=NULL WHERE id=? AND status='pending'");
    $id = (int)$request['id'];
    $stmt->bind_param('i', $id);
    $stmt->execute();
    $stmt->close();
    $conn->close();
    renderPage('Link kedaluwarsa', '<h1>Link verifikasi kedaluwarsa</h1><div class="notice error">Link hanya berlaku 10 menit. Kembali ke Telegram dan kirim /registrasi untuk membuat link baru.</div>', 410);
}

if (empty($_SESSION['csrf'])) {
    $_SESSION['csrf'] = bin2hex(random_bytes(32));
}
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $csrf = (string)($_POST['csrf'] ?? '');
    if (!hash_equals((string)$_SESSION['csrf'], $csrf)) {
        $error = 'Sesi formulir sudah berubah. Muat ulang halaman dan coba lagi.';
    } else {
        $username = trim((string)($_POST['username'] ?? ''));
        $password = (string)($_POST['password'] ?? '');
        try {
            $conn = db();
            $stmt = $conn->prepare('SELECT id, username, password_hash, nik_pegawai, display_name FROM dummy_login_accounts WHERE username = ? AND is_active = 1 LIMIT 1');
            $stmt->bind_param('s', $username);
            $stmt->execute();
            $account = $stmt->get_result()->fetch_assoc();
            $stmt->close();

            if (!$account || !password_verify($password, $account['password_hash'])) {
                $error = 'Username atau password tidak sesuai. Periksa akun dummy dan coba lagi.';
            } elseif (!hash_equals((string)$request['nik_pegawai'], (string)$account['nik_pegawai'])) {
                $stmt = $conn->prepare("UPDATE telegram_verification_requests SET notification_code='nik_mismatch', notification_sent_at=NULL, login_username=? WHERE id=? AND status='pending'");
                $rid = (int)$request['id'];
                $stmt->bind_param('si', $username, $rid);
                $stmt->execute();
                $stmt->close();
                $error = 'Akun login ini tidak sesuai dengan NIK yang dimasukkan di Telegram. Gunakan akun dummy yang memiliki NIK tersebut. Bot juga akan mengirim pemberitahuan.';
            } else {
                $conn->begin_transaction();
                try {
                    $rid = (int)$request['id'];
                    $lock = $conn->prepare("SELECT id, telegram_user_id, chat_id, nik_pegawai, status, expires_at FROM telegram_verification_requests WHERE id=? FOR UPDATE");
                    $lock->bind_param('i', $rid);
                    $lock->execute();
                    $current = $lock->get_result()->fetch_assoc();
                    $lock->close();

                    if (!$current || $current['status'] !== 'pending' || strtotime($current['expires_at']) < time()) {
                        throw new RuntimeException('Permintaan verifikasi sudah tidak aktif atau kedaluwarsa.');
                    }

                    $sid = (string)$current['telegram_user_id'];
                    $nik = (string)$current['nik_pegawai'];
                    $check = $conn->prepare('SELECT id FROM registrasi_telegram WHERE telegram_user_id=? LIMIT 1');
                    $check->bind_param('s', $sid);
                    $check->execute();
                    $existingUser = $check->get_result()->fetch_assoc();
                    $check->close();

                    $check = $conn->prepare('SELECT id FROM registrasi_telegram WHERE nik_pegawai=? LIMIT 1');
                    $check->bind_param('s', $nik);
                    $check->execute();
                    $existingNik = $check->get_result()->fetch_assoc();
                    $check->close();

                    if ($existingUser) {
                        $code = 'telegram_already_registered';
                        $status = 'rejected';
                    } elseif ($existingNik) {
                        $code = 'nik_already_registered';
                        $status = 'rejected';
                    } else {
                        $insert = $conn->prepare('INSERT INTO registrasi_telegram (telegram_user_id, chat_id, username, first_name, nik_pegawai) VALUES (?, ?, ?, ?, ?)');
                        $chatId = (string)$current['chat_id'];
                        $tgUsername = $request['username'] !== null ? (string)$request['username'] : null;
                        $firstName = $request['first_name'] !== null ? (string)$request['first_name'] : null;
                        $insert->bind_param('sssss', $sid, $chatId, $tgUsername, $firstName, $nik);
                        $insert->execute();
                        $insert->close();
                        $code = 'verification_success';
                        $status = 'verified';
                    }

                    $update = $conn->prepare("UPDATE telegram_verification_requests SET status=?, notification_code=?, notification_sent_at=NULL, verified_at=IF(?='verified', NOW(), verified_at), login_username=? WHERE id=?");
                    $update->bind_param('ssssi', $status, $code, $status, $username, $rid);
                    $update->execute();
                    $update->close();
                    $conn->commit();

                    if ($status === 'verified') {
                        session_regenerate_id(true);
                        $_SESSION['csrf'] = bin2hex(random_bytes(32));
                        $conn->close();
                        renderPage('Verifikasi berhasil', '<h1>Verifikasi berhasil</h1><div class="notice success">NIK sesuai dengan akun yang kamu gunakan. Registrasi sudah disimpan ke database lokal. Silakan kembali ke Telegram untuk melihat konfirmasi bot.</div>');
                    }
                    $conn->close();
                    if ($code === 'telegram_already_registered') {
                        renderPage('Akun sudah terdaftar', '<h1>Akun Telegram sudah terdaftar</h1><div class="notice error">Akun Telegram ini sudah memiliki registrasi. Registrasi baru ditolak.</div>');
                    }
                    renderPage('NIK sudah terdaftar', '<h1>NIK sudah terdaftar</h1><div class="notice error">NIK ini sudah terhubung ke akun Telegram lain. Registrasi ditolak.</div>');
                } catch (Throwable $e) {
                    $conn->rollback();
                    error_log('Dummy verification transaction error code: ' . $e->getCode());
                    $error = 'Registrasi belum dapat diselesaikan. Link mungkin sudah kedaluwarsa atau data sudah terdaftar. Kembali ke Telegram untuk mencoba kembali.';
                }
            }
            $conn->close();
        } catch (Throwable $e) {
            error_log('Dummy verification login error code: ' . $e->getCode());
            $error = 'Verifikasi tidak dapat diproses. Pastikan MySQL lokal aktif dan coba lagi.';
        }
    }
}

$body = '<h1>Verifikasi NIK</h1><p class="sub">Prototipe login dummy untuk menguji kecocokan NIK.</p>';
$body .= '<div class="notice">Masukkan username & password NIK yang kamu ajukan di telegram.</div>';
if ($error !== '') $body .= '<div class="notice error">' . h($error) . '</div>';
$body .= '<form method="post" action="">';
$body .= '<input type="hidden" name="token" value="' . h($token) . '">';
$body .= '<input type="hidden" name="csrf" value="' . h((string)$_SESSION['csrf']) . '">';
$body .= '<label for="username">Username</label><input id="username" name="username" autocomplete="username" required maxlength="100">';
$body .= '<label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" required>'; 
$body .= '<button type="submit">Login dan verifikasi</button></form>';
renderPage('Verifikasi NIK', $body);
