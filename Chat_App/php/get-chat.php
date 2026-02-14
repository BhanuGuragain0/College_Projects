<?php
// ============================================================================
// GET CHAT MESSAGES - SECURITY HARDENED
// ============================================================================

session_start();
include_once "config.php";
include_once "security.php";

// Require login
require_login();

$outgoing_id = $_SESSION['unique_id'];

// Validate and sanitize incoming_id
$incoming_id = filter_var($_GET['incoming_id'] ?? $_POST['incoming_id'] ?? '', FILTER_VALIDATE_INT);
if ($incoming_id === false || $incoming_id <= 0) {
    send_response('error', 'Invalid user ID');
}

// Use prepared statement to prevent SQL injection
$stmt = $conn->prepare("SELECT m.msg_id, m.msg, m.outgoing_msg_id, m.incoming_msg_id, 
                               u.fname, u.lname, u.img 
                        FROM messages m 
                        LEFT JOIN users u ON u.unique_id = m.outgoing_msg_id
                        WHERE (m.outgoing_msg_id = ? AND m.incoming_msg_id = ?) 
                           OR (m.outgoing_msg_id = ? AND m.incoming_msg_id = ?)
                        ORDER BY m.msg_id ASC");

if ($stmt === false) {
    log_security_event('GET_CHAT_ERROR', "Database prepare error: " . $conn->error, 'ERROR');
    send_response('error', 'Database error occurred');
}

$stmt->bind_param("iiii", $outgoing_id, $incoming_id, $incoming_id, $outgoing_id);

if (!$stmt->execute()) {
    log_security_event('GET_CHAT_ERROR', "Database execute error: " . $stmt->error, 'ERROR');
    send_response('error', 'Failed to fetch messages');
}

$result = $stmt->get_result();
$output = "";

if ($result->num_rows > 0) {
    while ($row = $result->fetch_assoc()) {
        // Escape message content to prevent XSS
        $msg = escape_html($row['msg']);
        
        if ($row['outgoing_msg_id'] == $outgoing_id) {
            $output .= '<div class="chat outgoing">
                            <div class="details">
                                <p>' . $msg . '</p>
                                <span class="time">now</span>
                            </div>
                        </div>';
        } else {
            $sender_name = escape_html(($row['fname'] ?? '') . ' ' . ($row['lname'] ?? ''));
            $img = escape_html($row['img'] ?? '');
            $output .= '<div class="chat incoming">
                            <img src="php/images/' . $img . '" alt="' . $sender_name . '">
                            <div class="details">
                                <p>' . $msg . '</p>
                                <span class="time">now</span>
                            </div>
                        </div>';
        }
    }
} else {
    $output .= '<div class="text">No messages are available. Once you send message they will appear here.</div>';
}

header('Content-Type: text/html; charset=utf-8');
echo $output;

$stmt->close();
$conn->close();
?>
