<?php
// ============================================================================
// RESET PASSWORD - SECURITY HARDENED
// ============================================================================

include_once "config.php";
include_once "security.php";

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    send_response('error', 'Invalid request method');
}

$token = validate_input($_POST['token'] ?? '');
$new_password = $_POST['new_password'] ?? '';
$password_confirm = $_POST['password_confirm'] ?? '';

if (empty($token) || empty($new_password)) {
    send_response('error', 'All fields are required');
}

if ($new_password !== $password_confirm) {
    send_response('error', 'Passwords do not match');
}

$password_errors = validate_password($new_password);
if (!empty($password_errors)) {
    send_response('error', 'Password is too weak. ' . implode(', ', $password_errors));
}

$stmt = $conn->prepare("SELECT email, created_at FROM password_resets WHERE token = ?");
if ($stmt === false) {
    log_security_event('RESET_PASSWORD_ERROR', "Database prepare error: " . $conn->error, 'ERROR');
    send_response('error', 'Database error occurred');
}

$stmt->bind_param("s", $token);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows === 0) {
    log_security_event('RESET_PASSWORD_ATTEMPT', "Invalid reset token used: $token", 'WARNING');
    send_response('error', 'Invalid or expired reset token');
}

$row = $result->fetch_assoc();
$email = $row['email'];
$created_at = $row['created_at'];

// Check token expiry (1 hour)
$expire_time = strtotime($created_at) + 3600;
if (time() > $expire_time) {
    log_security_event('RESET_PASSWORD_ATTEMPT', "Expired reset token used for: $email", 'WARNING');
    send_response('error', 'Reset token has expired. Please request a new one');
}

$hashed_password = password_hash($new_password, PASSWORD_BCRYPT, ['cost' => 12]);

$stmt2 = $conn->prepare("UPDATE users SET password = ? WHERE email = ?");
if ($stmt2 === false) {
    log_security_event('RESET_PASSWORD_ERROR', "Database prepare error: " . $conn->error, 'ERROR');
    send_response('error', 'Database error occurred');
}

$stmt2->bind_param("ss", $hashed_password, $email);

if ($stmt2->execute()) {
    $stmt3 = $conn->prepare("DELETE FROM password_resets WHERE token = ?");
    $stmt3->bind_param("s", $token);
    $stmt3->execute();
    $stmt3->close();
    
    log_security_event('RESET_PASSWORD_SUCCESS', "Password reset successful for: $email", 'INFO');
    send_response('success', 'Password has been reset successfully. Please login with your new password');
} else {
    log_security_event('RESET_PASSWORD_ERROR', "Failed to update password for: $email", 'ERROR');
    send_response('error', 'Failed to reset password. Please try again');
}

$stmt->close();
$stmt2->close();
$conn->close();
?>
