<?php
// =========================================================================
// LAYOUT / SIDEBAR
// =========================================================================
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
    <link rel="stylesheet" href="assets/style.css">
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
            <?php if (is_superadmin_username()): ?>
                <a class="nav-link <?= $route == 'manage_apis' ? 'active' : '' ?>" href="?page=manage_apis"><i class="fas fa-link me-2"></i> API Config</a>
            <?php endif; ?>
            <a class="nav-link text-danger mt-auto mb-4" href="?page=logout"><i class="fas fa-sign-out-alt me-2"></i> Logout</a>
        </nav>
    </div>

    <div class="main-content">
        <?php if ($message): ?><div class="alert alert-success border-0 shadow-sm"><?= $message ?></div><?php endif; ?>
        <?php if ($error): ?><div class="alert alert-danger border-0 shadow-sm"><?= $error ?></div><?php endif; ?>
        <?php include "views/$route.php"; ?>
    </div>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.3/js/bootstrap.bundle.min.js"></script>
    <script src="assets/script.js"></script>

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
