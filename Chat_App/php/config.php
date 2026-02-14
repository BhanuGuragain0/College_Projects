<?php
// ============================================================================
// DATABASE CONFIGURATION - SECURITY HARDENED
// ============================================================================

// Load environment variables from .env file if it exists
$env_file = __DIR__ . '/../.env';
if (file_exists($env_file)) {
    $env_vars = parse_ini_file($env_file);
    foreach ($env_vars as $key => $value) {
        putenv("$key=$value");
    }
}

// Get database credentials from environment variables (more secure)
$servername = getenv('DB_HOST') ?: 'localhost';
$username = getenv('DB_USER') ?: 'root';
$password = getenv('DB_PASS') ?: '';
$dbname = getenv('DB_NAME') ?: 'chat_app';

// Create connection with error handling
$conn = new mysqli($servername, $username, $password, $dbname);

// Set charset to UTF-8 to prevent charset-related SQL injection
$conn->set_charset("utf8mb4");

// Check connection and provide detailed error logging (but not to user)
if ($conn->connect_error) {
    // Log the error internally
    error_log("Database Connection Failed: " . $conn->connect_error, 3, __DIR__ . '/db_errors.log');
    
    // Show user-friendly error message
    die(json_encode([
        'status' => 'error',
        'message' => 'Database connection failed. Please try again later.'
    ]));
}

// Set error reporting for development/debugging
if (getenv('DEBUG_MODE') == 'true') {
    mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
}

// Define application constants
define('UPLOAD_DIR', __DIR__ . '/images/');
define('MAX_UPLOAD_SIZE', 5 * 1024 * 1024); // 5MB
define('ALLOWED_EXTENSIONS', ['jpeg', 'png', 'jpg']);
define('ALLOWED_MIME_TYPES', ['image/jpeg', 'image/jpg', 'image/png']);
define('SESSION_TIMEOUT', 30 * 60); // 30 minutes
define('MAX_LOGIN_ATTEMPTS', 5);
define('LOGIN_ATTEMPT_TIMEOUT', 15 * 60); // 15 minutes

// Security headers
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Content-Security-Policy: default-src \'self\'; script-src \'self\' \'unsafe-inline\'; style-src \'self\' \'unsafe-inline\'');

// Set secure session configuration
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') ? 1 : 0);
ini_set('session.cookie_samesite', 'Strict');

// Session timeout check
if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity'] > SESSION_TIMEOUT)) {
    session_unset();
    session_destroy();
    header('Location: ../login.html');
    exit;
}
$_SESSION['last_activity'] = time();
?>

