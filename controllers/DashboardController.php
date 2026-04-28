<?php
// =========================================================================
// DASHBOARD CONTROLLER (SEARCH FUNCTIONALITY)
// =========================================================================

function handleSearch($pdo) {
    header('Content-Type: application/json');

    $stmt = $pdo->prepare("SELECT role, package_expiry, searches_limit, searches_used, is_active FROM users WHERE id = ?");
    $stmt->execute([$_SESSION['user_id']]);
    $curr = $stmt->fetch();

    if (!$curr || $curr['is_active'] == 0) {
        echo json_encode(['error' => 'Account blocked or session invalid.']);
        exit;
    }

    if ($curr['role'] === 'user') {
        if (strtotime($curr['package_expiry']) < time()) {
            echo json_encode(['error' => 'Your subscription has expired.']);
            exit;
        }
        if ($curr['searches_used'] >= $curr['searches_limit']) {
            echo json_encode(['error' => 'Search limit reached.']);
            exit;
        }
    }

    $query = trim($_POST['query']);
    $apis = $pdo->query("SELECT api_name, api_url_template FROM apis WHERE is_active = 1")->fetchAll();

    $endpoints = [];
    foreach ($apis as $api) {
        $endpoints[$api['api_name']] = str_replace('[QUERY]', urlencode($query), $api['api_url_template']);
    }

    $results = execute_multi_curl($endpoints);
    $filtered = [];

    foreach ($results as $name => $data) {
        if (contains13DigitCNIC($data)) {
            $filtered[$name] = $data;
        }
    }

    if ($curr['role'] === 'user' && !empty($filtered)) {
        $pdo->prepare("UPDATE users SET searches_used = searches_used + 1 WHERE id = ?")->execute([$_SESSION['user_id']]);
    }

    echo json_encode($filtered);
    exit;
}
?>
