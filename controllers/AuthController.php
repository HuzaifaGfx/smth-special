<?php
// =========================================================================
// AUTHENTICATION CONTROLLER
// =========================================================================

function handleLogin($pdo) {
    global $error;
    
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        $_SESSION['captcha_n1'] = rand(1, 9);
        $_SESSION['captcha_n2'] = rand(1, 9);
        $_SESSION['captcha_ans'] = $_SESSION['captcha_n1'] + $_SESSION['captcha_n2'];
        return;
    }

    $u = trim($_POST['username'] ?? '');
    $p = $_POST['password'] ?? '';
    $user_captcha = $_POST['captcha_input'] ?? '';
    $current_ua = md5($_SERVER['HTTP_USER_AGENT']);

    if ((int)$user_captcha !== ($_SESSION['captcha_ans'] ?? -1)) {
        $error = "Invalid CAPTCHA answer.";
    } else {
        $stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
        $stmt->execute([$u]);
        $user = $stmt->fetch();

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
        } else {
            $error = "Invalid login credentials.";
        }
    }

    $_SESSION['captcha_n1'] = rand(1, 9);
    $_SESSION['captcha_n2'] = rand(1, 9);
    $_SESSION['captcha_ans'] = $_SESSION['captcha_n1'] + $_SESSION['captcha_n2'];
}

function handleChangePassword($pdo) {
    global $error, $message;

    $old_p = $_POST['old_password'] ?? '';
    $new_p = $_POST['new_password'] ?? '';
    $confirm_p = $_POST['confirm_password'] ?? '';

    $stmt = $pdo->prepare("SELECT password_hash FROM users WHERE id = ?");
    $stmt->execute([$_SESSION['user_id']]);
    $current_pwd = $stmt->fetchColumn();

    if ($old_p !== $current_pwd) {
        $error = "Incorrect current password.";
    } elseif ($new_p !== $confirm_p) {
        $error = "New passwords do not match.";
    } else {
        $pdo->prepare("UPDATE users SET password_hash = ? WHERE id = ?")->execute([$new_p, $_SESSION['user_id']]);
        $message = "Password updated successfully.";
    }
}
?>
