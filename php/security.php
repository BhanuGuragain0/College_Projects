<?php
// ============================================================================
// CYBER CHAT APP - SECURITY UTILITY FUNCTIONS
// Modernized with Enhanced Protection
// ============================================================================

/**
 * Validate and sanitize user input
 * @param string $data
 * @return string Sanitized data
 */
function validate_input($data) {
    $data = stripslashes($data);
    $data = htmlspecialchars($data, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    $data = trim($data);
    return $data;
}

/**
 * Validate email address
 * @param string $email
 * @return bool
 */
function validate_email($email) {
    return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
}

/**
 * Validate password strength
 * @param string $password
 * @return array
 */
function validate_password($password) {
    $errors = [];
    
    if (strlen($password) < 8) {
        $errors[] = "Password must be at least 8 characters long";
    }
    if (!preg_match('/[A-Z]/', $password)) {
        $errors[] = "Password must contain at least one uppercase letter";
    }
    if (!preg_match('/[a-z]/', $password)) {
        $errors[] = "Password must contain at least one lowercase letter";
    }
    if (!preg_match('/[0-9]/', $password)) {
        $errors[] = "Password must contain at least one number";
    }
    if (!preg_match('/[!@#$%^&*(),.?":{}|<>]/', $password)) {
        $errors[] = "Password must contain at least one special character";
    }
    
    return $errors;
}

/**
 * Validate name fields
 * @param string $name
 * @return bool
 */
function validate_name($name) {
    $name = trim($name);
    
    if (strlen($name) < 2 || strlen($name) > 50) {
        return false;
    }
    if (!preg_match('/^[a-zA-Z\s\-\']+$/', $name)) {
        return false;
    }
    
    return true;
}

/**
 * Validate file upload
 * @param array $file $_FILES['upload']
 * @return array ['valid' => bool, 'error' => string or null]
 */
function validate_file_upload($file) {
    if (!isset($file) || $file['error'] !== UPLOAD_ERR_OK) {
        return ['valid' => false, 'error' => 'File upload error'];
    }
    
    if ($file['size'] > MAX_UPLOAD_SIZE) {
        return ['valid' => false, 'error' => 'File size exceeds maximum allowed size (5MB)'];
    }
    
    $file_ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
    if (!in_array($file_ext, ALLOWED_EXTENSIONS)) {
        return ['valid' => false, 'error' => 'Invalid file type. Only JPEG, PNG, and JPG are allowed'];
    }
    
    $mime_type = mime_content_type($file['tmp_name']);
    if (!in_array($mime_type, ALLOWED_MIME_TYPES)) {
        return ['valid' => false, 'error' => 'Invalid file MIME type'];
    }
    
    return ['valid' => true, 'error' => null];
}

/**
 * Generate secure filename
 * @param string $original_filename
 * @return string
 */
function generate_secure_filename($original_filename) {
    $file_ext = strtolower(pathinfo($original_filename, PATHINFO_EXTENSION));
    $unique_id = uniqid(bin2hex(random_bytes(4)), true);
    return $unique_id . '.' . $file_ext;
}

/**
 * Log security events
 * @param string $event_type
 * @param string $message
 * @param string $severity (INFO, WARNING, ERROR, CRITICAL)
 */
function log_security_event($event_type, $message, $severity = 'INFO') {
    $timestamp = date('Y-m-d H:i:s');
    $ip_address = $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN';
    $user_id = $_SESSION['unique_id'] ?? 'ANONYMOUS';
    $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'UNKNOWN';
    
    $log_message = "[$timestamp] [$severity] [$event_type] [User: $user_id] [IP: $ip_address] [UA: $user_agent] $message\n";
    
    $log_file = __DIR__ . '/security.log';
    error_log($log_message, 3, $log_file);
}

/**
 * Generate CSRF token
 * @return string
 */
function generate_csrf_token() {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(CSRF_TOKEN_LENGTH / 2));
    }
    return $_SESSION['csrf_token'];
}

/**
 * Verify CSRF token
 * @param string $token
 * @return bool
 */
function verify_csrf_token($token) {
    if (empty($_SESSION['csrf_token']) || empty($token)) {
        return false;
    }
    return hash_equals($_SESSION['csrf_token'], $token);
}

/**
 * Check rate limiting
 * @param mysqli $conn
 * @param string $action
 * @param int $max_attempts
 * @param int $timeout_seconds
 * @return array ['allowed' => bool, 'remaining' => int]
 */
function check_rate_limit($conn, $action = 'general', $max_attempts = MAX_LOGIN_ATTEMPTS, $timeout_seconds = LOGIN_ATTEMPT_TIMEOUT) {
    $ip_address = $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN';
    $cutoff_time = date('Y-m-d H:i:s', time() - $timeout_seconds);
    
    // Clean up old entries
    $cleanup = $conn->prepare("DELETE FROM login_attempts WHERE attempted_at < ? AND success = 0");
    $cleanup->bind_param("s", $cutoff_time);
    $cleanup->execute();
    $cleanup->close();
    
    // Count recent attempts
    $stmt = $conn->prepare("SELECT COUNT(*) as attempt_count FROM login_attempts WHERE ip_address = ? AND attempted_at > ? AND success = 0");
    $stmt->bind_param("ss", $ip_address, $cutoff_time);
    $stmt->execute();
    $result = $stmt->get_result();
    $row = $result->fetch_assoc();
    $stmt->close();
    
    $attempt_count = $row['attempt_count'];
    
    return [
        'allowed' => $attempt_count < $max_attempts,
        'remaining' => max(0, $max_attempts - $attempt_count),
        'attempt_count' => $attempt_count
    ];
}

/**
 * Record login attempt
 * @param mysqli $conn
 * @param string $email
 * @param bool $success
 */
function record_login_attempt($conn, $email, $success) {
    $ip_address = $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN';
    
    $stmt = $conn->prepare("INSERT INTO login_attempts (ip_address, email, success) VALUES (?, ?, ?)");
    $stmt->bind_param("ssi", $ip_address, $email, $success);
    $stmt->execute();
    $stmt->close();
}

/**
 * Escape output for HTML context
 * @param string $data
 * @return string
 */
function escape_html($data) {
    return htmlspecialchars($data, ENT_QUOTES | ENT_HTML5, 'UTF-8');
}

/**
 * Escape output for JSON context
 * @param mixed $data
 * @return string
 */
function escape_json($data) {
    return json_encode($data, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP | JSON_UNESCAPED_UNICODE);
}

/**
 * Send JSON response
 * @param string $status
 * @param string $message
 * @param array $data
 */
function send_response($status, $message, $data = []) {
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(array_merge(
        ['status' => $status, 'message' => $message],
        $data
    ));
    exit;
}

/**
 * Check if user session is valid
 * @return bool
 */
function is_user_logged_in() {
    return isset($_SESSION['unique_id']) && !empty($_SESSION['unique_id']);
}

/**
 * Require user to be logged in
 */
function require_login() {
    if (!is_user_logged_in()) {
        send_response('error', 'Unauthorized access', ['redirect' => '../login.html']);
    }
}

/**
 * Get user data by unique_id
 * @param mysqli $conn
 * @param int $unique_id
 * @return array|null
 */
function get_user_by_id($conn, $unique_id) {
    if (!is_numeric($unique_id)) {
        return null;
    }
    
    $stmt = $conn->prepare("SELECT user_id, unique_id, fname, lname, email, img, status, last_seen FROM users WHERE unique_id = ?");
    $stmt->bind_param("i", $unique_id);
    $stmt->execute();
    $result = $stmt->get_result();
    $user = $result->fetch_assoc();
    $stmt->close();
    
    return $user;
}

/**
 * Get user data by email
 * @param mysqli $conn
 * @param string $email
 * @return array|null
 */
function get_user_by_email($conn, $email) {
    $email = validate_input($email);
    
    $stmt = $conn->prepare("SELECT user_id, unique_id, fname, lname, email, password, img, status, last_seen FROM users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();
    $user = $result->fetch_assoc();
    $stmt->close();
    
    return $user;
}

/**
 * Generate unique user ID
 * @param mysqli $conn
 * @return int
 */
function generate_unique_id($conn) {
    do {
        $unique_id = mt_rand(100000, 999999);
        $stmt = $conn->prepare("SELECT COUNT(*) as count FROM users WHERE unique_id = ?");
        $stmt->bind_param("i", $unique_id);
        $stmt->execute();
        $result = $stmt->get_result();
        $row = $result->fetch_assoc();
        $stmt->close();
    } while ($row['count'] > 0);
    
    return $unique_id;
}

/**
 * Format timestamp for display
 * @param string $timestamp
 * @return string
 */
function format_timestamp($timestamp) {
    $time = strtotime($timestamp);
    $now = time();
    $diff = $now - $time;
    
    if ($diff < 60) {
        return 'Just now';
    } elseif ($diff < 3600) {
        $mins = floor($diff / 60);
        return $mins . ' min' . ($mins > 1 ? 's' : '') . ' ago';
    } elseif ($diff < 86400) {
        $hours = floor($diff / 3600);
        return $hours . ' hour' . ($hours > 1 ? 's' : '') . ' ago';
    } else {
        return date('M j, Y g:i A', $time);
    }
}

/**
 * Generate password reset token
 * @return string
 */
function generate_reset_token() {
    return bin2hex(random_bytes(32));
}

/**
 * Hash password using bcrypt
 * @param string $password
 * @return string
 */
function hash_password($password) {
    return password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
}

/**
 * Verify password
 * @param string $password
 * @param string $hash
 * @return bool
 */
function verify_password($password, $hash) {
    return password_verify($password, $hash);
}
?>
