<?php
// =========================================================================
// TRACE VERISYS - FULL INTEGRATED: PDF EXPORT + PERMISSION CONTROL + FIXES
// =========================================================================

error_reporting(E_ALL);
ini_set('display_errors', 1);
session_start();

define('DB_PATH', __DIR__ . '/trace_verisys_db.sqlite');
define('LOGO_PATH', 'https://traceverisys.com/logo/logo.jpeg');

const PACKAGES = [
    'Package 1 Month' => ['limit' => 250, 'days' => 30],
    'Package 15 Days' => ['limit' => 150, 'days' => 15],
    'Package 2 Days' => ['limit' => 15, 'days' => 2],
];

// --- DATABASE SETUP ---
try {
    $pdo = new PDO("sqlite:" . DB_PATH);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);

    $pdo->exec("CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password_hash TEXT,
        role TEXT DEFAULT 'user',
        searches_limit INTEGER DEFAULT 0,
        searches_used INTEGER DEFAULT 0,
        package_name TEXT,
        package_expiry DATETIME,
        user_agent_hash TEXT,
        is_active INTEGER DEFAULT 1,
        can_export_pdf INTEGER DEFAULT 0, 
        created_by TEXT, 
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        renewed_at DATETIME,
        last_renewal_at DATETIME
    )");

    $checkColumn = $pdo->query("PRAGMA table_info(users)")->fetchAll();
    $columns = array_column($checkColumn, 'name');
    if (!in_array('can_export_pdf', $columns)) { $pdo->exec("ALTER TABLE users ADD COLUMN can_export_pdf INTEGER DEFAULT 0"); }
    if (!in_array('is_active', $columns)) { $pdo->exec("ALTER TABLE users ADD COLUMN is_active INTEGER DEFAULT 1"); }
    if (!in_array('renewed_at', $columns)) { $pdo->exec("ALTER TABLE users ADD COLUMN renewed_at DATETIME"); }
    if (!in_array('last_renewal_at', $columns)) { $pdo->exec("ALTER TABLE users ADD COLUMN last_renewal_at DATETIME"); }

    $pdo->exec("CREATE TABLE IF NOT EXISTS apis (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        api_name TEXT,
        api_url_template TEXT,
        is_active INTEGER DEFAULT 1
    )");
} catch (PDOException $e) { die("DB Error: " . $e->getMessage()); }

// --- HELPERS ---
function redirect($url) { header("Location: " . $url); exit; }
function is_logged_in() { return isset($_SESSION['user_id']); }
function get_role() { return $_SESSION['role'] ?? 'user'; }
function is_super() { return get_role() === 'superadmin'; }
function is_admin_or_super() { 
    $r = get_role();
    return is_logged_in() && ($r === 'admin' || $r === 'superadmin'); 
}

function contains13DigitCNIC($data) {
    if (is_array($data)) {
        foreach ($data as $val) if (contains13DigitCNIC($val)) return true;
    } elseif (is_string($data) || is_numeric($data)) {
        return preg_match('/\d{13}/', (string)$data);
    }
    return false;
}

function execute_multi_curl($apis) {
    $mh = curl_multi_init(); $handles = []; $results = [];
    foreach ($apis as $name => $url) {
        $ch = curl_init();
        curl_setopt_array($ch, [CURLOPT_URL => $url, CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 20, CURLOPT_SSL_VERIFYPEER => false]);
        curl_multi_add_handle($mh, $ch);
        $handles[$name] = $ch;
    }
    $running = null;
    do { curl_multi_exec($mh, $running); curl_multi_select($mh, 1.0); } while ($running > 0);
    foreach ($handles as $name => $ch) {
        $res = curl_multi_getcontent($ch);
        curl_multi_remove_handle($mh, $ch); curl_close($ch);
        $results[$name] = json_decode($res, true) ?: ["raw_response" => $res];
    }
    curl_multi_close($mh);
    return $results;
}

$route = $_GET['page'] ?? (is_logged_in() ? 'dashboard' : 'login');
if ($route === 'logout') { session_destroy(); redirect('?page=login'); }

$message = ''; $error = '';

if ($route === 'login' && $_SERVER['REQUEST_METHOD'] !== 'POST') {
    $_SESSION['captcha_n1'] = rand(1, 9);
    $_SESSION['captcha_n2'] = rand(1, 9);
    $_SESSION['captcha_ans'] = $_SESSION['captcha_n1'] + $_SESSION['captcha_n2'];
}

if ($route === 'login' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $u = trim($_POST['username'] ?? ''); $p = $_POST['password'] ?? '';
    $user_captcha = $_POST['captcha_input'] ?? '';
    $current_ua = md5($_SERVER['HTTP_USER_AGENT']);

    if ((int)$user_captcha !== ($_SESSION['captcha_ans'] ?? -1)) {
        $error = "Invalid CAPTCHA answer.";
    } else {
        $stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
        $stmt->execute([$u]); $user = $stmt->fetch();
        if ($user && $p === $user['password_hash']) {
            if ($user['is_active'] == 0) {
                $error = "This account has been blocked by the administrator.";
            } else {
                if ($user['role'] !== 'superadmin') {
                    if (empty($user['user_agent_hash'])) {
                        $pdo->prepare("UPDATE users SET user_agent_hash = ? WHERE id = ?")->execute([$current_ua, $user['id']]);
                    } elseif ($user['user_agent_hash'] !== $current_ua) {
                        $error = "This account is locked to another device. Contact Admin.";
                    }
                }
                if (empty($error)) {
                    $_SESSION['user_id'] = $user['id']; 
                    $_SESSION['username'] = $user['username']; 
                    $_SESSION['role'] = $user['role'];
                    redirect('?page=dashboard');
                }
            }
        } else { $error = "Invalid login credentials."; }
    }
    $_SESSION['captcha_n1'] = rand(1, 9);
    $_SESSION['captcha_n2'] = rand(1, 9);
    $_SESSION['captcha_ans'] = $_SESSION['captcha_n1'] + $_SESSION['captcha_n2'];
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && is_logged_in()) {
    $action = $_POST['action'] ?? '';
    if ($action === 'change_pwd') {
        $old_p = $_POST['old_password'] ?? '';
        $new_p = $_POST['new_password'] ?? '';
        $confirm_p = $_POST['confirm_password'] ?? '';
        $stmt = $pdo->prepare("SELECT password_hash FROM users WHERE id = ?");
        $stmt->execute([$_SESSION['user_id']]);
        $current_pwd = $stmt->fetchColumn();
        if ($old_p !== $current_pwd) { $error = "Incorrect current password."; } 
        elseif ($new_p !== $confirm_p) { $error = "New passwords do not match."; } 
        else {
            $pdo->prepare("UPDATE users SET password_hash = ? WHERE id = ?")->execute([$new_p, $_SESSION['user_id']]);
            $message = "Password updated successfully.";
        }
    }
    if (is_admin_or_super()) {
        if ($action === 'create_user') {
            $role = $_POST['new_role'] ?? 'user';
            $new_u = trim($_POST['new_username'] ?? '');
            $pkg = $_POST['package_name'] ?? 'Package 1 Month';
            $expiry = ($role === 'user') ? date('Y-m-d H:i:s', strtotime("+".PACKAGES[$pkg]['days']." days")) : '2099-12-31';
            $limit = ($role === 'user') ? PACKAGES[$pkg]['limit'] : 999999;
            $creator = $_SESSION['username'] ?? 'System';
            try {
                $pdo->prepare("INSERT INTO users (username, password_hash, role, searches_limit, package_name, package_expiry, created_by, created_at) VALUES (?,?,?,?,?,?,?,?)")
                    ->execute([$new_u, '20202020', $role, $limit, $pkg, $expiry, $creator, date('Y-m-d H:i:s')]);
                $message = "Account $new_u created successfully.";
            } catch (Exception $e) { $error = "User already exists."; }
        } elseif ($action === 'reset_device') {
            $pdo->prepare("UPDATE users SET user_agent_hash = NULL WHERE id = ?")->execute([$_POST['user_id']]);
            $message = "Device lock reset.";
        } elseif ($action === 'toggle_pdf' && is_super()) {
            $val = (int)$_POST['pdf_status'];
            $pdo->prepare("UPDATE users SET can_export_pdf = ? WHERE id = ?")->execute([$val, $_POST['user_id']]);
            $message = "PDF Access updated.";
        } elseif ($action === 'renew_user') {
            $uid = $_POST['user_id'];
            $pkg = $_POST['package_name'];
            $expiry = date('Y-m-d H:i:s', strtotime("+".PACKAGES[$pkg]['days']." days"));
            $limit = PACKAGES[$pkg]['limit'];
            $pdo->prepare("UPDATE users SET package_name = ?, package_expiry = ?, searches_limit = ?, searches_used = 0, last_renewal_at = ? WHERE id = ?")
                ->execute([$pkg, $expiry, $limit, date('Y-m-d H:i:s'), $uid]);
            $message = "User subscription renewed.";
        } 
        
        // --- SUPER ADMIN ONLY ACTIONS ---
        if (is_super()) {
            if ($action === 'delete_user') {
                $pdo->prepare("DELETE FROM users WHERE id = ?")->execute([$_POST['user_id']]);
                $message = "Account deleted successfully.";
            } elseif ($action === 'toggle_block') {
                $status = (int)$_POST['status'];
                $pdo->prepare("UPDATE users SET is_active = ? WHERE id = ?")->execute([$status, $_POST['user_id']]);
                $message = $status ? "User unblocked." : "User blocked.";
            } elseif ($action === 'change_username') {
                $new_uname = trim($_POST['new_username']);
                try {
                    $pdo->prepare("UPDATE users SET username = ? WHERE id = ?")->execute([$new_uname, $_POST['user_id']]);
                    $message = "Username updated to $new_uname.";
                } catch (Exception $e) { $error = "Username already taken."; }
            } elseif ($action === 'add_api') {
                $pdo->prepare("INSERT INTO apis (api_name, api_url_template) VALUES (?,?)")->execute([$_POST['api_name'], $_POST['api_url']]);
                $message = "API source added.";
            } elseif ($action === 'delete_api') {
                $pdo->prepare("DELETE FROM apis WHERE id = ?")->execute([$_POST['api_id']]);
                $message = "API removed.";
            }
        }
    }
}

if ($route === 'dashboard' && $_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['query'])) {
    header('Content-Type: application/json');
    $stmt = $pdo->prepare("SELECT role, package_expiry, searches_limit, searches_used, is_active FROM users WHERE id = ?");
    $stmt->execute([$_SESSION['user_id']]);
    $curr = $stmt->fetch();
    if (!$curr || $curr['is_active'] == 0) { echo json_encode(['error' => 'Account blocked or session invalid.']); exit; }
    if ($curr['role'] === 'user') {
        if (strtotime($curr['package_expiry']) < time()) { echo json_encode(['error' => 'Your subscription has expired.']); exit; }
        if ($curr['searches_used'] >= $curr['searches_limit']) { echo json_encode(['error' => 'Search limit reached.']); exit; }
    }
    $query = trim($_POST['query']);
    $apis = $pdo->query("SELECT api_name, api_url_template FROM apis WHERE is_active = 1")->fetchAll();
    $endpoints = [];
    foreach ($apis as $api) $endpoints[$api['api_name']] = str_replace('[QUERY]', urlencode($query), $api['api_url_template']);
    $results = execute_multi_curl($endpoints);
    $filtered = [];
    foreach ($results as $name => $data) if (contains13DigitCNIC($data)) $filtered[$name] = $data;
    if ($curr['role'] === 'user' && !empty($filtered)) {
        $pdo->prepare("UPDATE users SET searches_used = searches_used + 1 WHERE id = ?")->execute([$_SESSION['user_id']]);
    }
    echo json_encode($filtered); exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TRACE VERISYS</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.3/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/html2pdf.js/0.10.1/html2pdf.bundle.min.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        html, body { margin: 0; padding: 0; }
        body { background: #f1f5f9; font-family: 'Segoe UI', sans-serif; display: flex; min-height: 100vh; }
        .sidebar { width: 260px; background: #0f172a; color: white; flex-shrink: 0; position: sticky; top:0; height: 100vh; overflow-y: auto; transition: 0.3s; }
        .main-content { flex-grow: 1; padding: 40px; width: 100%; }
        .nav-link { color: #94a3b8; padding: 12px 20px; transition: 0.2s; display: block; text-decoration: none; }
        .nav-link:hover, .nav-link.active { color: white; background: #1e293b; border-left: 4px solid #3b82f6; }
        .result-card { background: white; border-radius: 12px; overflow: hidden; border: none; box-shadow: 0 4px 12px rgba(0,0,0,0.05); margin-bottom: 20px; page-break-inside: avoid; break-inside: avoid; }
        @media (max-width: 768px) { body { flex-direction: column; } .sidebar { width: 100%; height: auto; position: relative; } .main-content { padding: 20px; } .sidebar .nav { flex-direction: row; flex-wrap: wrap; } .nav-link { flex: 1; text-align: center; } }
        .result-header { background: #1e293b; color: white; padding: 10px 15px; font-size: 0.8rem; font-weight: bold; }
        .result-table { width: 100%; margin: 0; border-collapse: collapse; }
        .result-table td { padding: 10px 15px; border-bottom: 1px solid #f1f5f9; font-size: 0.85rem; }
        .result-label { background: #f8fafc; width: 35%; color: #64748b; font-weight: bold; text-transform: uppercase; font-size: 0.7rem; }
        .img-detect { max-width: 120px; border-radius: 6px; cursor: pointer; }
        .pkg-card { background: white; border-radius: 15px; padding: 25px; box-shadow: 0 10px 30px rgba(0,0,0,0.05); }
        .captcha-box { background: #f8fafc; border: 1px dashed #cbd5e1; border-radius: 8px; padding: 10px; text-align: center; margin-bottom: 15px; }
        .stat-card { background: white; border-radius: 12px; padding: 20px; box-shadow: 0 4px 12px rgba(0,0,0,0.05); text-align: center; }
        .stat-number { font-size: 2.5rem; font-weight: bold; color: #3b82f6; }
        .stat-label { color: #64748b; font-size: 0.9rem; margin-top: 8px; }
    </style>
</head>
<body>

<?php if (is_logged_in()): 
    $p_stmt = $pdo->prepare("SELECT can_export_pdf FROM users WHERE id = ?");
    $p_stmt->execute([$_SESSION['user_id']]);
    $user_can_pdf = $p_stmt->fetchColumn();
?>
    <div class="sidebar d-flex flex-column shadow">
        <div class="p-4 text-center">
            <img src="<?= LOGO_PATH ?>" width="65" class="rounded-circle mb-2 border shadow-sm">
            <h6 class="mb-0 text-white fw-bold d-none d-md-block">TRACE VERISYS</h6>
            <span class="badge bg-primary mt-1"><?= strtoupper(get_role()) ?></span>
        </div>
        <nav class="nav flex-column mt-3">
            <a class="nav-link <?= $route == 'dashboard' ? 'active' : '' ?>" href="?page=dashboard"><i class="fas fa-search me-2"></i> Intelligence Tracker</a>
            <a class="nav-link <?= $route == 'my_package' ? 'active' : '' ?>" href="?page=my_package"><i class="fas fa-box me-2"></i> My Package</a>
            <a class="nav-link <?= $route == 'settings' ? 'active' : '' ?>" href="?page=settings"><i class="fas fa-key me-2"></i> Change Password</a>
            <?php if (is_admin_or_super()): ?>
                <a class="nav-link <?= $route == 'manage_users' ? 'active' : '' ?>" href="?page=manage_users"><i class="fas fa-users-cog me-2"></i> Accounts</a>
                <a class="nav-link <?= $route == 'blocked_users' ? 'active' : '' ?>" href="?page=blocked_users"><i class="fas fa-ban me-2"></i> Blocked Users</a>
            <?php endif; ?>
            <?php if (is_super()): ?>
                <a class="nav-link <?= $route == 'manage_apis' ? 'active' : '' ?>" href="?page=manage_apis"><i class="fas fa-link me-2"></i> API Config</a>
            <?php endif; ?>
            <a class="nav-link text-danger mt-auto mb-4" href="?page=logout"><i class="fas fa-sign-out-alt me-2"></i> Logout</a>
        </nav>
    </div>

    <div class="main-content">
        <?php if ($message): ?><div class="alert alert-success border-0 shadow-sm"><?= $message ?></div><?php endif; ?>
        <?php if ($error): ?><div class="alert alert-danger border-0 shadow-sm"><?= $error ?></div><?php endif; ?>

        <?php if ($route === 'dashboard'): ?>
            <div class="mb-4 d-flex justify-content-between align-items-center">
                <h3 class="fw-bold">Database Scan</h3>
                <button id="download-pdf" class="btn btn-danger btn-sm fw-bold" style="display:none;" onclick="exportPDF()">
                    <i class="fas fa-file-pdf me-2"></i> PDF
                </button>
            </div>
            <div class="input-group input-group-lg shadow-sm mb-5">
                <input type="text" id="query" class="form-control border-0 px-4" placeholder="Enter your Query...">
                <button class="btn btn-primary px-4 fw-bold" onclick="doSearch()" id="btn-s">SCAN</button>
            </div>
            <div id="results" class="row g-4"></div>

        <?php elseif ($route === 'my_package'): 
            $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
            $stmt->execute([$_SESSION['user_id']]);
            $me = $stmt->fetch();
            $rem = ($me['searches_limit'] - $me['searches_used']);
            $percent = ($me['searches_limit'] > 0) ? ($me['searches_used'] / $me['searches_limit']) * 100 : 0;
        ?>
            <div class="mb-4"><h3 class="fw-bold">Subscription Details</h3></div>
            <div class="row">
                <div class="col-md-6">
                    <div class="pkg-card">
                        <h5 class="text-muted small text-uppercase fw-bold mb-4">Active Plan</h5>
                        <h2 class="fw-bold text-primary mb-1"><?= $me['package_name'] ?? 'Custom Plan' ?></h2>
                        <p class="text-muted mb-2">Created: <span class="text-dark fw-bold"><?= date('M d, Y H:i', strtotime($me['created_at'])) ?></span></p>
                        <p class="text-muted mb-4">Expires on: <span class="text-dark fw-bold"><?= date('M d, Y', strtotime($me['package_expiry'])) ?></span></p>
                        <?php if ($me['last_renewal_at']): ?><p class="text-muted mb-4">Last Renewed: <span class="text-dark fw-bold"><?= date('M d, Y H:i', strtotime($me['last_renewal_at'])) ?></span></p><?php endif; ?>
                        <div class="progress mb-4" style="height: 10px; border-radius: 10px;">
                            <div class="progress-bar bg-primary" style="width: <?= $percent ?>%"></div>
                        </div>
                        <div class="row g-3">
                            <div class="col-6"><div class="p-3 bg-light rounded text-center"><h4 class="mb-0 fw-bold"><?= $rem ?></h4><span class="text-muted small">Remaining</span></div></div>
                            <div class="col-6"><div class="p-3 bg-light rounded text-center"><h4 class="mb-0 fw-bold"><?= $me['searches_used'] ?></h4><span class="text-muted small">Consumed</span></div></div>
                        </div>
                    </div>
                </div>
            </div>

        <?php elseif ($route === 'settings'): ?>
            <div class="mb-4"><h3 class="fw-bold">Account Settings</h3></div>
            <div class="col-md-5">
                <div class="pkg-card">
                    <h5 class="fw-bold mb-4">Change Password</h5>
                    <form method="POST">
                        <input type="hidden" name="action" value="change_pwd">
                        <div class="mb-3">
                            <label class="small fw-bold mb-1">Current Password</label>
                            <input type="password" name="old_password" class="form-control" required>
                        </div>
                        <div class="mb-3">
                            <label class="small fw-bold mb-1">New Password</label>
                            <input type="password" name="new_password" class="form-control" required>
                        </div>
                        <div class="mb-4">
                            <label class="small fw-bold mb-1">Confirm New Password</label>
                            <input type="password" name="confirm_password" class="form-control" required>
                        </div>
                        <button class="btn btn-primary w-100 fw-bold">UPDATE PASSWORD</button>
                    </form>
                </div>
            </div>

        <?php elseif ($route === 'manage_users'): 
            $total_users = $pdo->query("SELECT COUNT(*) FROM users WHERE role = 'user'")->fetchColumn();
        ?>
            <div class="mb-4 d-flex justify-content-between align-items-center">
                <h3 class="fw-bold">Manage Accounts</h3>
                <div class="stat-card" style="width: 200px;">
                    <div class="stat-number"><?= $total_users ?></div>
                    <div class="stat-label">Total Users</div>
                </div>
            </div>

            <div class="card p-4 mb-4 border-0 shadow-sm">
                <h5 class="fw-bold mb-3">Create New Account</h5>
                <form method="POST" class="row g-2">
                    <input type="hidden" name="action" value="create_user">
                    <div class="col-md-3"><input type="text" name="new_username" class="form-control" placeholder="Username" required></div>
                    <div class="col-md-3">
                        <?php if ($_SESSION['role'] === 'superadmin'): ?>
    <?php if ($_SESSION['role'] === 'superadmin'): ?>
    <select name="new_role" required>
        <option value="user">User</option>
        <option value="admin">Admin</option>
    </select>
<?php else: ?>
    <select name="new_role" required>
        <option value="user">User</option>
    </select>
<?php endif; ?>

<?php else: ?>
    <select name="new_role" required>
        <option value="user">User</option>
    </select>
<?php endif; ?>

                    </div>
                    <div class="col-md-3">
                        <select name="package_name" class="form-select">
                            <?php foreach(PACKAGES as $name => $v): ?><option value="<?= $name ?>"><?= $name ?></option><?php endforeach; ?>
                        </select>
                    </div>
                    <div class="col-md-3"><button class="btn btn-primary w-100 fw-bold">CREATE</button></div>
                </form>
            </div>

            <div class="card p-4 border-0 shadow-sm overflow-auto">
                <div class="d-flex justify-content-between align-items-center mb-4">
                    <h5 class="fw-bold mb-0">All Accounts</h5>
                    <input type="text" id="userSearch" class="form-control form-control-sm w-25" placeholder="Search user..." onkeyup="filterUsers()">
                </div>
                <table class="table align-middle" id="userTable">
                    <thead><tr><th>Username</th><th>Role</th><th>Created</th><th>Expiry</th><th>Last Renewed</th><th>Credits</th><th>Status</th><th>PDF</th><th class="text-center">Actions</th></tr></thead>
                    <tbody>
                        <?php foreach($pdo->query("SELECT * FROM users ORDER BY id DESC") as $u): ?>
                        <tr class="<?= $u['is_active'] ? '' : 'table-danger' ?>">
                            <td>
                                <div class="fw-bold u-name"><?= $u['username'] ?></div>
                                <div class="text-muted" style="font-size: 10px;">Created by: <?= $u['created_by'] ?? 'System' ?></div>
                            </td>
                            <td><span class="badge bg-light text-dark border"><?= $u['role'] ?></span></td>
                            <td><small><?= date('M d, Y', strtotime($u['created_at'])) ?></small></td>
                            <td><small><?= date('M d, Y', strtotime($u['package_expiry'])) ?></small></td>
                            <td>
                                <?php if($u['last_renewal_at']): ?>
                                    <small><?= date('M d, Y', strtotime($u['last_renewal_at'])) ?></small>
                                <?php else: ?>
                                    <small class="text-muted">Never</small>
                                <?php endif; ?>
                            </td>
                            <td><?= $u['role']=='user' ? ($u['searches_limit'] - $u['searches_used']) : '∞' ?></td>
                            <td>
                                <?php if(is_super()): ?>
                                <form method="POST" class="d-inline">
                                    <input type="hidden" name="action" value="toggle_block">
                                    <input type="hidden" name="user_id" value="<?= $u['id'] ?>">
                                    <input type="hidden" name="status" value="<?= $u['is_active'] ? 0 : 1 ?>">
                                    <button type="submit" class="btn btn-sm <?= $u['is_active'] ? 'btn-outline-success' : 'btn-danger' ?>">
                                        <?= $u['is_active'] ? 'Active' : 'Blocked' ?>
                                    </button>
                                </form>
                                <?php else: ?>
                                    <span class="badge bg-<?= $u['is_active'] ? 'success' : 'danger' ?>"><?= $u['is_active'] ? 'Active' : 'Blocked' ?></span>
                                <?php endif; ?>
                            </td>
                            <td>
                                <?php if(is_super()): ?>
                                <form method="POST" class="d-inline">
                                    <input type="hidden" name="action" value="toggle_pdf">
                                    <input type="hidden" name="user_id" value="<?= $u['id'] ?>">
                                    <input type="hidden" name="pdf_status" value="<?= $u['can_export_pdf'] ? 0 : 1 ?>">
                                    <button type="submit" class="btn btn-sm <?= $u['can_export_pdf'] ? 'btn-success' : 'btn-secondary' ?>">
                                        <?= $u['can_export_pdf'] ? 'Yes' : 'No' ?>
                                    </button>
                                </form>
                                <?php else: ?>
                                    <span class="badge bg-light text-dark"><?= $u['can_export_pdf'] ? 'Yes' : 'No' ?></span>
                                <?php endif; ?>
                            </td>
                            <td class="text-center">
                                <form method="POST" class="d-inline">
                                    <input type="hidden" name="action" value="reset_device">
                                    <input type="hidden" name="user_id" value="<?= $u['id'] ?>">
                                    <button class="btn btn-sm btn-outline-warning" title="Reset Device"><i class="fas fa-mobile-alt"></i></button>
                                </form>
                                <button class="btn btn-sm btn-outline-success" data-bs-toggle="modal" data-bs-target="#renewModal<?= $u['id'] ?>" title="Renew"><i class="fas fa-sync-alt"></i></button>
                                
                                <?php if(is_super()): ?>
                                    <button class="btn btn-sm btn-outline-primary" data-bs-toggle="modal" data-bs-target="#editModal<?= $u['id'] ?>" title="Edit Username"><i class="fas fa-edit"></i></button>
                                    <form method="POST" class="d-inline" onsubmit="return confirm('Permanently delete this user?');">
                                        <input type="hidden" name="action" value="delete_user">
                                        <input type="hidden" name="user_id" value="<?= $u['id'] ?>">
                                        <button class="btn btn-sm btn-outline-danger" title="Delete"><i class="fas fa-trash"></i></button>
                                    </form>
                                <?php endif; ?>
                            </td>
                        </tr>

                        <div class="modal fade" id="editModal<?= $u['id'] ?>" tabindex="-1">
                            <div class="modal-dialog modal-sm modal-dialog-centered">
                                <div class="modal-content border-0 shadow">
                                    <div class="modal-header"><h6 class="modal-title fw-bold">Edit Username</h6><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
                                    <form method="POST">
                                        <div class="modal-body">
                                            <input type="hidden" name="action" value="change_username">
                                            <input type="hidden" name="user_id" value="<?= $u['id'] ?>">
                                            <input type="text" name="new_username" class="form-control" value="<?= $u['username'] ?>" required>
                                        </div>
                                        <div class="modal-footer border-0"><button type="submit" class="btn btn-primary w-100 fw-bold">SAVE CHANGES</button></div>
                                    </form>
                                </div>
                            </div>
                        </div>

                        <div class="modal fade" id="renewModal<?= $u['id'] ?>" tabindex="-1">
                            <div class="modal-dialog modal-sm modal-dialog-centered">
                                <div class="modal-content border-0 shadow">
                                    <div class="modal-header"><h6 class="modal-title fw-bold">Renew Account</h6><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
                                    <form method="POST">
                                        <div class="modal-body">
                                            <input type="hidden" name="action" value="renew_user">
                                            <input type="hidden" name="user_id" value="<?= $u['id'] ?>">
                                            <select name="package_name" class="form-select">
                                                <?php foreach(PACKAGES as $pn => $pv): ?><option value="<?= $pn ?>"><?= $pn ?></option><?php endforeach; ?>
                                            </select>
                                        </div>
                                        <div class="modal-footer border-0"><button type="submit" class="btn btn-primary w-100 fw-bold">RENEW NOW</button></div>
                                    </form>
                                </div>
                            </div>
                        </div>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>

        <?php elseif ($route === 'blocked_users' && is_admin_or_super()): 
            $blocked = $pdo->query("SELECT * FROM users WHERE is_active = 0 ORDER BY id DESC")->fetchAll();
        ?>
            <div class="mb-4"><h3 class="fw-bold">Blocked Users</h3></div>
            
            <?php if (count($blocked) > 0): ?>
            <div class="card p-4 border-0 shadow-sm overflow-auto">
                <div class="d-flex justify-content-between align-items-center mb-4">
                    <h5 class="fw-bold mb-0">All Blocked Accounts (<?= count($blocked) ?>)</h5>
                    <input type="text" id="blockedSearch" class="form-control form-control-sm w-25" placeholder="Search user..." onkeyup="filterBlockedUsers()">
                </div>
                <table class="table align-middle table-danger" id="blockedTable">
                    <thead><tr><th>Username</th><th>Role</th><th>Created</th><th>Blocked Date</th><th>Package</th><th>Created By</th><th class="text-center">Actions</th></tr></thead>
                    <tbody>
                        <?php foreach($blocked as $u): ?>
                        <tr>
                            <td>
                                <div class="fw-bold b-name"><?= $u['username'] ?></div>
                            </td>
                            <td><span class="badge bg-light text-dark border"><?= $u['role'] ?></span></td>
                            <td><small><?= date('M d, Y H:i', strtotime($u['created_at'])) ?></small></td>
                            <td><small><?= date('M d, Y', strtotime($u['package_expiry'])) ?></small></td>
                            <td><small><?= $u['package_name'] ?? 'N/A' ?></small></td>
                            <td><small><?= $u['created_by'] ?? 'System' ?></small></td>
                            <td class="text-center">
                                <?php if(is_super()): ?>
                                <form method="POST" class="d-inline">
                                    <input type="hidden" name="action" value="toggle_block">
                                    <input type="hidden" name="user_id" value="<?= $u['id'] ?>">
                                    <input type="hidden" name="status" value="1">
                                    <button type="submit" class="btn btn-sm btn-outline-success">Unblock</button>
                                </form>
                                <form method="POST" class="d-inline" onsubmit="return confirm('Permanently delete this user?');">
                                    <input type="hidden" name="action" value="delete_user">
                                    <input type="hidden" name="user_id" value="<?= $u['id'] ?>">
                                    <button class="btn btn-sm btn-outline-danger">Delete</button>
                                </form>
                                <?php else: ?>
                                <span class="text-muted small">No actions available</span>
                                <?php endif; ?>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
            <?php else: ?>
            <div class="alert alert-info border-0 shadow-sm">
                <i class="fas fa-info-circle me-2"></i> No blocked users at the moment.
            </div>
            <?php endif; ?>

        <?php elseif ($route === 'manage_apis' && is_super()): ?>
            <div class="card p-4 mb-4 border-0 shadow-sm">
                <h5 class="fw-bold mb-3">Add API Source</h5>
                <form method="POST" class="row g-2">
                    <input type="hidden" name="action" value="add_api">
                    <div class="col-md-4"><input type="text" name="api_name" class="form-control" placeholder="API Name" required></div>
                    <div class="col-md-6"><input type="text" name="api_url" class="form-control" placeholder="URL with [QUERY]" required></div>
                    <div class="col-md-2"><button class="btn btn-primary w-100 fw-bold">ADD</button></div>
                </form>
            </div>
            <div class="card p-4 border-0 shadow-sm overflow-auto">
                <h5 class="fw-bold mb-4">Active API Endpoints</h5>
                <table class="table">
                    <thead><tr><th>Name</th><th>URL</th><th>Action</th></tr></thead>
                    <tbody>
                        <?php foreach($pdo->query("SELECT * FROM apis") as $api): ?>
                        <tr><td class="fw-bold"><?= $api['api_name'] ?></td><td class="small text-muted"><?= $api['api_url_template'] ?></td><td>
                            <form method="POST"><input type="hidden" name="action" value="delete_api"><input type="hidden" name="api_id" value="<?= $api['id'] ?>"><button class="btn btn-sm btn-danger">Delete</button></form>
                        </td></tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        <?php endif; ?>
    </div>
    
    <script>
        const USER_CAN_PDF = <?= (int)$user_can_pdf ?>;
        function exportPDF() {
            const query = document.getElementById('query').value.trim() || 'Results';
            const element = document.getElementById('results');
            const opt = { margin: [0.3, 0.3], filename: 'Report_' + query + '.pdf', image: { type: 'jpeg', quality: 0.98 }, html2canvas: { scale: 2, useCORS: true }, jsPDF: { unit: 'in', format: 'a4', orientation: 'portrait' } };
            html2pdf().set(opt).from(element).save();
        }
        function filterUsers() {
            let input = document.getElementById("userSearch").value.toUpperCase();
            let tr = document.getElementById("userTable").getElementsByTagName("tr");
            for (let i = 1; i < tr.length; i++) {
                let td = tr[i].getElementsByClassName("u-name")[0];
                if (td) tr[i].style.display = (td.textContent || td.innerText).toUpperCase().indexOf(input) > -1 ? "" : "none";
            }
        }
        function filterBlockedUsers() {
            let input = document.getElementById("blockedSearch").value.toUpperCase();
            let tr = document.getElementById("blockedTable").getElementsByTagName("tr");
            for (let i = 1; i < tr.length; i++) {
                let td = tr[i].getElementsByClassName("b-name")[0];
                if (td) tr[i].style.display = (td.textContent || td.innerText).toUpperCase().indexOf(input) > -1 ? "" : "none";
            }
        }
        function renderContent(data) {
            if (!data) return "--";
            if (typeof data === 'object' && !Array.isArray(data)) {
                let subRows = '';
                for (const [key, val] of Object.entries(data)) subRows += `<tr><td class="result-label" style="font-size:10px;">${key.replace(/_/g, ' ')}</td><td>${renderContent(val)}</td></tr>`;
                return `<div class="nested-table-container"><table class="result-table">${subRows}</table></div>`;
            }
            return (typeof data === 'string' && data.startsWith('data:image')) ? `<img src="${data}" class="img-detect" onclick="window.open(this.src)">` : data;
        }
        async function doSearch() {
            const q = document.getElementById('query').value.trim();
            const resDiv = document.getElementById('results');
            const pdfBtn = document.getElementById('download-pdf');
            if (!q) return;
            pdfBtn.style.display = 'none';
            resDiv.innerHTML = '<div class="col-12 text-center p-5"><div class="spinner-border text-primary"></div></div>';
            try {
                const response = await fetch('?page=dashboard', { method: 'POST', headers: {'Content-Type': 'application/x-www-form-urlencoded'}, body: 'query=' + encodeURIComponent(q) });
                const data = await response.json();
                if (data.error) { resDiv.innerHTML = `<div class="col-12"><div class="alert alert-danger">${data.error}</div></div>`; return; }
                resDiv.innerHTML = ''; let recordCounter = 1; let hasResults = false;
                for (const [apiName, body] of Object.entries(data)) {
                    let items = Array.isArray(body) ? body : (typeof body === 'object' ? Object.values(body).find(v => Array.isArray(v)) || [body] : [body]);
                    items.forEach((item) => {
                        if (typeof item !== 'object' || item === null) return;
                        hasResults = true;
                        const col = document.createElement('div'); col.className = 'col-lg-4 col-md-6 col-sm-12'; 
                        let innerRows = '';
                        for (const [k, v] of Object.entries(item)) innerRows += `<tr><td class="result-label">${k.replace(/_/g, ' ')}</td><td class="fw-bold">${renderContent(v)}</td></tr>`;
                        col.innerHTML = `<div class="result-card shadow-sm"><div class="result-header d-flex justify-content-between"><span>${apiName}</span><span class="badge bg-primary">RECORD ${recordCounter}</span></div><table class="result-table">${innerRows}</table></div>`;
                        resDiv.appendChild(col); recordCounter++;
                    });
                }
                if (hasResults && USER_CAN_PDF) pdfBtn.style.display = 'block';
            } catch (e) { resDiv.innerHTML = '<div class="alert alert-danger">Error fetching data.</div>'; }
        }
    </script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.3/js/bootstrap.bundle.min.js"></script>

<?php else: ?>
    <div class="d-flex w-100 align-items-center justify-content-center bg-dark" style="height: 100vh;">
        <div class="card p-4 shadow-lg border-0" style="width: 360px;">
            <div class="text-center mb-4"><img src="<?= LOGO_PATH ?>" width="80" class="rounded-circle shadow"><p class="mt-2 text-muted small fw-bold">Your crime-solving Partner</p></div>
            <?php if($error): ?><div class="alert alert-danger small"><?= $error ?></div><?php endif; ?>
            <form method="POST" action="?page=login">
                <input type="text" name="username" class="form-control mb-3" placeholder="Username" required>
                <input type="password" name="password" class="form-control mb-3" placeholder="Password" required>
                <div class="captcha-box"><span class="fw-bold text-primary fs-5"><?= $_SESSION['captcha_n1'] ?> + <?= $_SESSION['captcha_n2'] ?> = ?</span></div>
                <input type="number" name="captcha_input" class="form-control mb-3" placeholder="Enter Answer" required>
                <button class="btn btn-primary w-100 py-2 fw-bold">AUTHORIZE</button>
            </form>
        </div>
    </div>
<?php endif; ?>
</body>
</html>
