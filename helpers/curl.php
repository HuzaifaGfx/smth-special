<?php
// =========================================================================
// CURL & API HELPERS
// =========================================================================

function execute_multi_curl($apis) {
    $mh = curl_multi_init();
    $handles = [];
    $results = [];

    foreach ($apis as $name => $url) {
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 20,
            CURLOPT_SSL_VERIFYPEER => false
        ]);
        curl_multi_add_handle($mh, $ch);
        $handles[$name] = $ch;
    }

    $running = null;
    do {
        curl_multi_exec($mh, $running);
        curl_multi_select($mh, 1.0);
    } while ($running > 0);

    foreach ($handles as $name => $ch) {
        $res = curl_multi_getcontent($ch);
        curl_multi_remove_handle($mh, $ch);
        curl_close($ch);
        $results[$name] = json_decode($res, true) ?: ["raw_response" => $res];
    }

    curl_multi_close($mh);
    return $results;
}

function get_active_apis($pdo) {
    return $pdo->query("SELECT api_name, api_url_template FROM apis WHERE is_active = 1")->fetchAll();
}
?>
