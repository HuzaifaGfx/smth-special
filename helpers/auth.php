<?php
// =========================================================================
// AUTHENTICATION HELPERS
// =========================================================================

function redirect($url) {
    header("Location: " . $url);
    exit;
}

function is_logged_in() {
    return isset($_SESSION['user_id']);
}

function get_role() {
    return $_SESSION['role'] ?? 'user';
}

function is_super() {
    return get_role() === 'superadmin';
}

function is_admin_or_super() {
    $r = get_role();
    return is_logged_in() && ($r === 'admin' || $r === 'superadmin');
}

function require_login() {
    if (!is_logged_in()) {
        redirect('?page=login');
    }
}

function require_admin() {
    if (!is_admin_or_super()) {
        die('Access Denied');
    }
}

function require_super() {
    if (!is_super()) {
        die('Access Denied');
    }
}

function logout() {
    session_destroy();
    redirect('?page=login');
}
?>
