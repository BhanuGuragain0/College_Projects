<?php
session_start();
include_once "config.php";
include_once "security.php";

if (is_user_logged_in()) {
    $logout_id = filter_var($_GET['logout_id'] ?? $_SESSION['unique_id'], FILTER_VALIDATE_INT);
    
    if ($logout_id === false || $logout_id <= 0) {
        log_security_event('LOGOUT_ERROR', 'Invalid logout ID attempted', 'WARNING');
        header("Location: ../login.html");
        exit;
    }
    
    if ($logout_id != $_SESSION['unique_id']) {
        log_security_event('LOGOUT_ERROR', "Attempt to logout different user", 'WARNING');
        header("Location: ../login.html");
        exit;
    }
    
    $status = "Offline now";
    $stmt = $conn->prepare("UPDATE users SET status = ? WHERE unique_id = ?");
    
    if ($stmt) {
        $stmt->bind_param("si", $status, $logout_id);
        
        if ($stmt->execute()) {
            log_security_event('LOGOUT_SUCCESS', "User $logout_id logged out", 'INFO');
            session_unset();
            session_destroy();
            header("Location: ../login.html");
        } else {
            log_security_event('LOGOUT_ERROR', "Failed to update status: " . $stmt->error, 'ERROR');
        }
        $stmt->close();
    }
} else {
    header("Location: ../login.html");
}
$conn->close();
?>

