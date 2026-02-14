<?php
// ============================================================================
// SECURITY UTILITY FUNCTIONS
// ============================================================================

/**
 * Validate and sanitize user input
 * @param string $data
 * @return string Sanitized data
 */
function validate_input($data) {
    $data = stripslashes($data);
    $data = htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
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
    
    // Name should be 2-50 characters, contain only letters, spaces, hyphens
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
    
    // Check file size
    if ($file['size'] > MAX_UPLOAD_SIZE) {
        return ['valid' => false, 'error' => 'File size exceeds maximum allowed size (5MB)'];
    }
    
    // Check file extension
    $file_ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
    if (!in_array($file_ext, ALLOWED_EXTENSIONS)) {
        return ['valid' => false, 'error' => 'Invalid file type. Only JPEG, PNG, and JPG are allowed'];
    }
    
    // Check MIME type
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
    
    $log_message = "[$timestamp] [$severity] [$event_type] [User: $user_id] [IP: $ip_address] $message\n";
    
    error_log($log_message, 3, __DIR__ . '/security.log');
}

/**
 * Verify CSRF token
 * @param string $token
 * @return bool
 */
function verify_csrf_token($token) {
    if (!isset($_SESSION['csrf_token'])) {
        return false;
    }
    
    return hash_equals($_SESSION['csrf_token'], $token);
}

/**
 * Generate CSRF token
 * @return string
 */
function generate_csrf_token() {
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

/**
 * Check rate limiting
 * @param string $action
 * @param int $max_attempts
 * @param int $timeout
 * @return array ['allowed' => bool, 'remaining' => int]
 */
function check_rate_limit($action, $max_attempts = MAX_LOGIN_ATTEMPTS, $timeout = LOGIN_ATTEMPT_TIMEOUT) {
    $ip_address = $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN';
    $key = "ratelimit_${action}_${ip_address}";
    
    // In production, use Redis or similar for this
    // This is a simple file-based approach
    $file_path = sys_get_temp_dir() . '/' . md5($key) . '.txt';
    
    $current_time = time();
    $attempts_data = [];
    
    if (file_exists($file_path)) {
        $content = file_get_contents($file_path);
        $attempts_data = json_decode($content, true);
        
        // Remove old attempts
        $attempts_data = array_filter($attempts_data, function($timestamp) use ($current_time, $timeout) {
            return ($current_time - $timestamp) < $timeout;
        });
    }
    
    $attempt_count = count($attempts_data);
    
    if ($attempt_count >= $max_attempts) {
        return ['allowed' => false, 'remaining' => 0];
    }
    
    $attempts_data[] = $current_time;
    file_put_contents($file_path, json_encode($attempts_data));
    
    return ['allowed' => true, 'remaining' => $max_attempts - count($attempts_data)];
}

/**
 * Escape output for HTML context
 * @param string $data
 * @return string
 */
function escape_html($data) {
    return htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
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
    
    $stmt = $conn->prepare("SELECT user_id, unique_id, fname, lname, email, img, status FROM users WHERE unique_id = ?");
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
    
    $stmt = $conn->prepare("SELECT user_id, unique_id, fname, lname, email, password, img, status FROM users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();
    $user = $result->fetch_assoc();
    $stmt->close();
    
    return $user;
}

?>
