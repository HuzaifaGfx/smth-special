<?php
// =========================================================================
// UTILITY FUNCTIONS
// =========================================================================

function contains13DigitCNIC($data) {
    if (is_array($data)) {
        foreach ($data as $val) {
            if (contains13DigitCNIC($val)) return true;
        }
    } elseif (is_string($data) || is_numeric($data)) {
        return preg_match('/\d{13}/', (string)$data);
    }
    return false;
}

function get_user_by_id($pdo, $id) {
    $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
    $stmt->execute([$id]);
    return $stmt->fetch();
}

function get_all_users($pdo) {
    return $pdo->query("SELECT * FROM users ORDER BY id DESC")->fetchAll();
}

function get_blocked_users($pdo) {
    return $pdo->query("SELECT * FROM users WHERE is_active = 0 ORDER BY id DESC")->fetchAll();
}

function get_user_count($pdo) {
    return $pdo->query("SELECT COUNT(*) FROM users WHERE role = 'user'")->fetchColumn();
}

function format_date($date, $format = 'M d, Y') {
    return date($format, strtotime($date));
}

function format_datetime($date, $format = 'M d, Y H:i') {
    return date($format, strtotime($date));
}
?>
