<?php
// ============================================================================
// CYBER CHAT APP - INSERT MESSAGE ENDPOINT
// Modernized with Security & JSON Responses
// ============================================================================

session_start();
include_once "config.php";
include_once "security.php";

header('Content-Type: application/json');

// Require login
require_login();

// Only accept POST requests
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    send_response('error', 'Invalid request method');
}

// Get and validate inputs
$outgoing_id = $_SESSION['unique_id'];
$incoming_id = filter_var($_POST['incoming_id'] ?? '', FILTER_VALIDATE_INT);
$message = isset($_POST['message']) ? trim($_POST['message']) : '';

// Validate incoming_id
if ($incoming_id === false || $incoming_id <= 0) {
    log_security_event('MESSAGE_ERROR', "Invalid incoming_id: " . ($_POST['incoming_id'] ?? 'NULL'), 'WARNING');
    send_response('error', 'Invalid recipient');
}

// Prevent self-messaging
if ($incoming_id == $outgoing_id) {
    log_security_event('MESSAGE_ERROR', "User attempted to message themselves", 'WARNING');
    send_response('error', 'Cannot message yourself');
}

// Verify recipient exists
$recipient = get_user_by_id($conn, $incoming_id);
if (!$recipient) {
    log_security_event('MESSAGE_ERROR', "Message to non-existent user: $incoming_id", 'WARNING');
    send_response('error', 'Recipient not found');
}

// Validate message
if (empty($message)) {
    send_response('error', 'Message cannot be empty');
}

// Check message length
if (strlen($message) > 10000) {
    send_response('error', 'Message too long (max 10,000 characters)');
}

// Sanitize message
$message = htmlspecialchars($message, ENT_QUOTES | ENT_HTML5, 'UTF-8');

// Insert message
$stmt = $conn->prepare("INSERT INTO messages (incoming_msg_id, outgoing_msg_id, msg, created_at) VALUES (?, ?, ?, NOW())");
$stmt->bind_param("iis", $incoming_id, $outgoing_id, $message);

if ($stmt->execute()) {
    $msg_id = $stmt->insert_id;
    $stmt->close();
    
    log_security_event('MESSAGE_SENT', "Message $msg_id sent from $outgoing_id to $incoming_id", 'INFO');
    
    send_response('success', 'Message sent', [
        'msg_id' => $msg_id,
        'timestamp' => date('Y-m-d H:i:s')
    ]);
} else {
    $error = $stmt->error;
    $stmt->close();
    
    log_security_event('MESSAGE_ERROR', "Failed to send message: $error", 'ERROR');
    send_response('error', 'Failed to send message');
}
?>
