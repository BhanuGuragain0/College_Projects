<?php
// ============================================================================
// VALIDATE USER FOR PASSWORD RESET - SECURITY HARDENED
// ============================================================================

session_start();
include_once "config.php";
include_once "security.php";

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    send_response('error', 'Invalid request method');
}

$fname = validate_input($_POST['name'] ?? '');
$email = validate_input($_POST['email'] ?? '');

if (empty($fname) || empty($email)) {
    send_response('error', 'All fields are required');
}

if (!validate_email($email)) {
    send_response('error', 'Invalid email address');
}

$stmt = $conn->prepare("SELECT user_id, unique_id, fname, email FROM users WHERE fname = ? AND email = ?");
if ($stmt === false) {
    log_security_event('VALIDATE_USER_ERROR', "Database prepare error: " . $conn->error, 'ERROR');
    send_response('error', 'Database error occurred');
}

$stmt->bind_param("ss", $fname, $email);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows > 0) {
    $row = $result->fetch_assoc();
    $reset_token = bin2hex(random_bytes(32));
    $expires_at = date("Y-m-d H:i:s", strtotime('+1 hour'));
    
    $stmt2 = $conn->prepare("INSERT INTO password_resets (email, token, created_at) VALUES (?, ?, ?)");
    if ($stmt2 === false) {
        log_security_event('VALIDATE_USER_ERROR', "Database prepare error: " . $conn->error, 'ERROR');
        send_response('error', 'Failed to create reset token');
    }
    
    $stmt2->bind_param("sss", $email, $reset_token, $expires_at);
    
    if ($stmt2->execute()) {
        log_security_event('VALIDATE_USER_SUCCESS', "Password reset token created for: $email", 'INFO');
        send_response('success', 'An email with a password reset link has been sent', ['token' => $reset_token]);
    } else {
        log_security_event('VALIDATE_USER_ERROR', "Failed to insert reset token: " . $stmt2->error, 'ERROR');
        send_response('error', 'Failed to create reset token');
    }
    $stmt2->close();
} else {
    log_security_event('VALIDATE_USER_ATTEMPT', "Password reset attempt for non-existent user: $email", 'WARNING');
    send_response('error', 'User not found. Please check your name and email');
}

$stmt->close();
$conn->close();
?>

