<?php
// =========================================================================
// DATABASE CONFIGURATION & SETUP
// =========================================================================

define('DB_PATH', __DIR__ . '/../trace_verisys_db.sqlite');
define('LOGO_PATH', 'https://traceverisys.com/logo/logo.jpeg');

error_reporting(E_ALL);
ini_set('display_errors', 1);

try {
    $pdo = new PDO("sqlite:" . DB_PATH);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);

    // Users table
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

    // Add missing columns if they don't exist
    $checkColumn = $pdo->query("PRAGMA table_info(users)")->fetchAll();
    $columns = array_column($checkColumn, 'name');
    if (!in_array('can_export_pdf', $columns)) { $pdo->exec("ALTER TABLE users ADD COLUMN can_export_pdf INTEGER DEFAULT 0"); }
    if (!in_array('is_active', $columns)) { $pdo->exec("ALTER TABLE users ADD COLUMN is_active INTEGER DEFAULT 1"); }
    if (!in_array('renewed_at', $columns)) { $pdo->exec("ALTER TABLE users ADD COLUMN renewed_at DATETIME"); }
    if (!in_array('last_renewal_at', $columns)) { $pdo->exec("ALTER TABLE users ADD COLUMN last_renewal_at DATETIME"); }

    // APIs table
    $pdo->exec("CREATE TABLE IF NOT EXISTS apis (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        api_name TEXT,
        api_url_template TEXT,
        is_active INTEGER DEFAULT 1
    )");

} catch (PDOException $e) {
    die("DB Error: " . $e->getMessage());
}
?>
