<?php
// =========================================================================
// TRACE VERISYS - MAIN ENTRY POINT (REFACTORED)
// =========================================================================

session_start();

// Load configuration
require_once __DIR__ . '/config/database.php';
require_once __DIR__ . '/config/packages.php';

// Load helpers
require_once __DIR__ . '/helpers/auth.php';
require_once __DIR__ . '/helpers/utils.php';
require_once __DIR__ . '/helpers/curl.php';

// Load controllers
require_once __DIR__ . '/controllers/AuthController.php';
require_once __DIR__ . '/controllers/DashboardController.php';
require_once __DIR__ . '/controllers/AdminController.php';

// Initialize variables
$route = $_GET['page'] ?? (is_logged_in() ? 'dashboard' : 'login');
$message = '';
$error = '';

// Handle logout
if ($route === 'logout') {
    logout();
}

// Handle GET routes
if ($route === 'login' && $_SERVER['REQUEST_METHOD'] !== 'POST') {
    $_SESSION['captcha_n1'] = rand(1, 9);
    $_SESSION['captcha_n2'] = rand(1, 9);
    $_SESSION['captcha_ans'] = $_SESSION['captcha_n1'] + $_SESSION['captcha_n2'];
}

// Handle POST requests
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Login logic
    if ($route === 'login') {
        handleLogin($pdo);
    }

    // Dashboard search (AJAX)
    if ($route === 'dashboard' && isset($_POST['query'])) {
        handleSearch($pdo);
    }

    // Logged in POST requests
    if (is_logged_in()) {
        $action = $_POST['action'] ?? '';

        // Change password (all users)
        if ($action === 'change_pwd') {
            handleChangePassword($pdo);
        }

        // Admin actions
        if (is_admin_or_super()) {
            handleAdminActions($pdo);
        }
    }
}

// Redirect to login if not logged in (except for login page)
if (!is_logged_in() && $route !== 'login') {
    $route = 'login';
}

// Load layout
include 'views/layout.php';
?>
