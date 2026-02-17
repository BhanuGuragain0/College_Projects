<?php
// ============================================================================
// CYBER CHAT APP - DATABASE CONFIGURATION
// Modernized with SSE Support & Enhanced Security
// ============================================================================

// Prevent direct access
define('CHAT_APP', true);

// Load environment variables from .env file
$env_file = __DIR__ . '/../.env';
if (file_exists($env_file)) {
    $lines = file($env_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($lines as $line) {
        if (strpos($line, '#') === 0) continue;
        if (strpos($line, '=') !== false) {
            list($key, $value) = explode('=', $line, 2);
            $key = trim($key);
            $value = trim($value);
            if (!empty($key)) {
                putenv("$key=$value");
                $_ENV[$key] = $value;
            }
        }
    }
}

// Database configuration
$servername = getenv('DB_HOST') ?: 'localhost';
$username = getenv('DB_USER') ?: 'root';
$password = getenv('DB_PASS') ?: '';
$dbname = getenv('DB_NAME') ?: 'chat_app';

// Create connection
$conn = new mysqli($servername, $username, $password, $dbname);

// Set charset to UTF-8
$conn->set_charset("utf8mb4");

// Check connection
if ($conn->connect_error) {
    error_log("Database Connection Failed: " . $conn->connect_error);
    die(json_encode([
        'status' => 'error',
        'message' => 'Database connection failed. Please try again later.'
    ]));
}

// Error reporting configuration
if (getenv('DEBUG_MODE') === 'true') {
    mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
    error_reporting(E_ALL);
    ini_set('display_errors', 1);
} else {
    error_reporting(0);
    ini_set('display_errors', 0);
}

// Application constants
define('UPLOAD_DIR', __DIR__ . '/images/');
define('MAX_UPLOAD_SIZE', (int)(getenv('MAX_UPLOAD_SIZE') ?: 5 * 1024 * 1024));
define('ALLOWED_EXTENSIONS', ['jpeg', 'png', 'jpg']);
define('ALLOWED_MIME_TYPES', ['image/jpeg', 'image/jpg', 'image/png']);
define('SESSION_TIMEOUT', (int)(getenv('SESSION_TIMEOUT') ?: 30 * 60));
define('MAX_LOGIN_ATTEMPTS', (int)(getenv('MAX_LOGIN_ATTEMPTS') ?: 5));
define('LOGIN_ATTEMPT_TIMEOUT', (int)(getenv('LOGIN_ATTEMPT_TIMEOUT') ?: 15 * 60));
define('CSRF_TOKEN_LENGTH', (int)(getenv('CSRF_TOKEN_LENGTH') ?: 64));
define('APP_URL', getenv('APP_URL') ?: 'http://localhost');

// Security headers
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');
header('Referrer-Policy: strict-origin-when-cross-origin');
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: blob:; connect-src 'self';");
header('Permissions-Policy: geolocation=(), microphone=(), camera=()');

// Session security configuration
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') ? 1 : 0);
ini_set('session.cookie_samesite', 'Strict');
ini_set('session.use_strict_mode', 1);
ini_set('session.gc_maxlifetime', SESSION_TIMEOUT);

// Start session
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Session timeout check
if (isset($_SESSION['last_activity'])) {
    if ((time() - $_SESSION['last_activity']) > SESSION_TIMEOUT) {
        session_unset();
        session_destroy();
        if (!headers_sent()) {
            header('Location: ../login.html');
            exit;
        }
    }
}
$_SESSION['last_activity'] = time();

// Regenerate session ID periodically for security
if (isset($_SESSION['created']) && (time() - $_SESSION['created'] > 300)) {
    session_regenerate_id(true);
    $_SESSION['created'] = time();
} elseif (!isset($_SESSION['created'])) {
    $_SESSION['created'] = time();
}

// Timezone configuration
date_default_timezone_set('UTC');

// Helper function for SSE headers
function set_sse_headers() {
    header('Content-Type: text/event-stream');
    header('Cache-Control: no-cache');
    header('Connection: keep-alive');
    header('X-Accel-Buffering: no');
    
    // Disable output buffering
    if (ob_get_level()) {
        ob_end_clean();
    }
    ob_implicit_flush(true);
    
    // Set script execution time for SSE
    set_time_limit(0);
}
?>

