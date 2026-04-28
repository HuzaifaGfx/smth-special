<?php
// =========================================================================
// ADMIN CONTROLLER (USER MANAGEMENT)
// =========================================================================

function handleAdminActions($pdo) {
    global $error, $message;
    
    $action = $_POST['action'] ?? '';

    // Admin & Super Admin actions
    if (is_admin_or_super()) {
        if ($action === 'create_user') {
            $role = $_POST['new_role'] ?? 'user';
            $new_u = trim($_POST['new_username'] ?? '');
            $pkg = $_POST['package_name'] ?? 'Package 1 Month';
            $expiry = ($role === 'user') ? date('Y-m-d H:i:s', strtotime("+" . PACKAGES[$pkg]['days'] . " days")) : '2099-12-31';
            $limit = ($role === 'user') ? PACKAGES[$pkg]['limit'] : 999999;
            $creator = $_SESSION['username'] ?? 'System';

            try {
                $pdo->prepare("INSERT INTO users (username, password_hash, role, searches_limit, package_name, package_expiry, created_by, created_at) VALUES (?,?,?,?,?,?,?,?)")
                    ->execute([$new_u, '20202020', $role, $limit, $pkg, $expiry, $creator, date('Y-m-d H:i:s')]);
                $message = "Account $new_u created successfully.";
            } catch (Exception $e) {
                $error = "User already exists.";
            }
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
            $expiry = date('Y-m-d H:i:s', strtotime("+" . PACKAGES[$pkg]['days'] . " days"));
            $limit = PACKAGES[$pkg]['limit'];
            $pdo->prepare("UPDATE users SET package_name = ?, package_expiry = ?, searches_limit = ?, searches_used = 0, last_renewal_at = ? WHERE id = ?")
                ->execute([$pkg, $expiry, $limit, date('Y-m-d H:i:s'), $uid]);
            $message = "User subscription renewed.";
        }
    }

    // Super Admin only actions
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
            } catch (Exception $e) {
                $error = "Username already taken.";
            }
        } elseif ($action === 'add_api') {
            $pdo->prepare("INSERT INTO apis (api_name, api_url_template) VALUES (?,?)")->execute([$_POST['api_name'], $_POST['api_url']]);
            $message = "API source added.";
        } elseif ($action === 'delete_api') {
            $pdo->prepare("DELETE FROM apis WHERE id = ?")->execute([$_POST['api_id']]);
            $message = "API removed.";
        }
    }
}
?>
