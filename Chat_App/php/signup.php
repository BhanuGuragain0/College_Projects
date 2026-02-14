<?php
// ============================================================================
// USER REGISTRATION - SECURITY HARDENED
// ============================================================================

session_start();
include_once "config.php";
include_once "security.php";

// Only accept POST requests
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    send_response('error', 'Invalid request method');
}

// Verify CSRF token
if (!isset($_POST['csrf_token']) || !verify_csrf_token($_POST['csrf_token'])) {
    send_response('error', 'CSRF token validation failed');
}

// Check rate limiting
$rate_limit = check_rate_limit('signup');
if (!$rate_limit['allowed']) {
    log_security_event('SIGNUP_ATTEMPT', 'Rate limit exceeded for signup', 'WARNING');
    send_response('error', 'Too many signup attempts. Please try again later.');
}

// Validate and sanitize inputs
$fname = validate_input($_POST['fname'] ?? '');
$lname = validate_input($_POST['lname'] ?? '');
$email = validate_input($_POST['email'] ?? '');
$password = $_POST['password'] ?? '';
$password_confirm = $_POST['password_confirm'] ?? '';

// Validate required fields
if (empty($fname) || empty($lname) || empty($email) || empty($password)) {
    send_response('error', 'All input fields are required');
}

// Validate name fields
if (!validate_name($fname)) {
    send_response('error', 'First name is invalid (2-50 characters, letters only)');
}

if (!validate_name($lname)) {
    send_response('error', 'Last name is invalid (2-50 characters, letters only)');
}

// Validate email
if (!validate_email($email)) {
    send_response('error', "$email is not a valid email address");
}

// Validate password match
if ($password !== $password_confirm) {
    send_response('error', 'Passwords do not match');
}

// Validate password strength
$password_errors = validate_password($password);
if (!empty($password_errors)) {
    send_response('error', 'Password is too weak. ' . implode(', ', $password_errors));
}

// Check if email already exists
$existing_user = get_user_by_email($conn, $email);
if ($existing_user !== null) {
    log_security_event('SIGNUP_ATTEMPT', "Attempt to register with existing email: $email", 'INFO');
    send_response('error', 'This email address is already registered');
}

// Validate file upload
if (!isset($_FILES['image']) || $_FILES['image']['error'] !== UPLOAD_ERR_OK) {
    send_response('error', 'Please upload a profile image');
}

$file_validation = validate_file_upload($_FILES['image']);
if (!$file_validation['valid']) {
    send_response('error', $file_validation['error']);
}

// Create upload directory if it doesn't exist
if (!is_dir(UPLOAD_DIR)) {
    mkdir(UPLOAD_DIR, 0755, true);
}

// Generate secure filename and move uploaded file
$new_img_name = generate_secure_filename($_FILES['image']['name']);
$upload_path = UPLOAD_DIR . $new_img_name;

if (!move_uploaded_file($_FILES['image']['tmp_name'], $upload_path)) {
    log_security_event('SIGNUP_ERROR', "Failed to upload image for user: $email", 'ERROR');
    send_response('error', 'Failed to upload image. Please try again');
}

// Hash password using bcrypt (more secure than md5)
$hashed_password = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);

// Generate unique user ID
$unique_id = mt_rand(100000, 999999);

// Set initial status
$status = "Active now";

// Use prepared statement to prevent SQL injection
$stmt = $conn->prepare("INSERT INTO users (unique_id, fname, lname, email, password, img, status) VALUES (?, ?, ?, ?, ?, ?, ?)");

if ($stmt === false) {
    log_security_event('SIGNUP_ERROR', "Database prepare error: " . $conn->error, 'ERROR');
    send_response('error', 'Database error occurred. Please try again');
}

$stmt->bind_param("issssss", $unique_id, $fname, $lname, $email, $hashed_password, $new_img_name, $status);

if (!$stmt->execute()) {
    // Delete uploaded image on signup failure
    unlink($upload_path);
    log_security_event('SIGNUP_ERROR', "Database execute error: " . $stmt->error, 'ERROR');
    send_response('error', 'Failed to create account. Please try again');
}

$stmt->close();

// Verify user was created and set session
$new_user = get_user_by_email($conn, $email);
if ($new_user === null) {
    // Clean up: Delete uploaded image on failure
    unlink($upload_path);
    log_security_event('SIGNUP_ERROR', "User verification failed after INSERT for email: $email", 'ERROR');
    send_response('error', 'Account creation failed. Please try again');
}

// Set session
$_SESSION['unique_id'] = $new_user['unique_id'];

log_security_event('SIGNUP_SUCCESS', "New user registered: $email (ID: {$new_user['unique_id']})", 'INFO');

send_response('success', 'Account created successfully', [
    'user_id' => $new_user['unique_id'],
    'fname' => $new_user['fname']
]);

$conn->close();
?>
