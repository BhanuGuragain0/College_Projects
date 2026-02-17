<?php
// ============================================================================
// CYBER CHAT APP - LOGIN ENDPOINT
// Modernized with Rate Limiting & CSRF Protection
// ============================================================================

session_start();
include_once "config.php";
include_once "security.php";

header('Content-Type: application/json');

// Only accept POST requests
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    send_response('error', 'Invalid request method');
}

// Verify CSRF token
if (!isset($_POST['csrf_token']) || !verify_csrf_token($_POST['csrf_token'])) {
    log_security_event('LOGIN_ATTEMPT', 'CSRF token validation failed', 'WARNING');
    send_response('error', 'Security validation failed');
}

// Check rate limiting
$rate_limit = check_rate_limit($conn, 'login');
if (!$rate_limit['allowed']) {
    log_security_event('LOGIN_ATTEMPT', 'Rate limit exceeded', 'WARNING');
    send_response('error', 'Too many login attempts. Please try again later.');
}

// Validate and sanitize inputs
$email = validate_input($_POST['email'] ?? '');
$password = $_POST['password'] ?? '';

// Validate required fields
if (empty($email) || empty($password)) {
    send_response('error', 'All input fields are required');
}

// Validate email format
if (!validate_email($email)) {
    record_login_attempt($conn, $email, false);
    send_response('error', 'Invalid email format');
}

// Retrieve user
$user = get_user_by_email($conn, $email);

if (!$user) {
    record_login_attempt($conn, $email, false);
    log_security_event('LOGIN_ATTEMPT', "Failed login attempt for non-existent email: $email", 'WARNING');
    send_response('error', 'Email or Password is incorrect');
}

// Verify password
if (!verify_password($password, $user['password'])) {
    record_login_attempt($conn, $email, false);
    log_security_event('LOGIN_ATTEMPT', "Failed login attempt for user: {$user['email']}", 'WARNING');
    send_response('error', 'Email or Password is incorrect');
}

// Record successful login
record_login_attempt($conn, $email, true);

// Update user status
$status = "Active now";
$stmt = $conn->prepare("UPDATE users SET status = ?, last_seen = NOW() WHERE unique_id = ?");
$stmt->bind_param("si", $status, $user['unique_id']);
$status_updated = $stmt->execute();
$stmt->close();

if (!$status_updated) {
    log_security_event('LOGIN_ERROR', "Failed to update status for user: {$user['email']}", 'ERROR');
    send_response('error', 'Login failed. Please try again.');
}

// Create session
$_SESSION['unique_id'] = $user['unique_id'];
$_SESSION['user_email'] = $user['email'];
$_SESSION['user_name'] = $user['fname'] . ' ' . $user['lname'];
$_SESSION['created'] = time();

// Log successful login
log_security_event('LOGIN_SUCCESS', "User logged in: {$user['email']} (ID: {$user['unique_id']})", 'INFO');

send_response('success', 'Login successful', [
    'user_id' => $user['unique_id'],
    'fname' => $user['fname'],
    'redirect' => 'users.php'
]);
?>
