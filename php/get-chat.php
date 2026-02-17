<?php
// ============================================================================
// CYBER CHAT APP - SSE CHAT ENDPOINT
// Server-Sent Events for Real-time Message Streaming
// ============================================================================

session_start();
include_once "config.php";
include_once "security.php";

// Check authentication
require_login();

// Get and validate incoming user ID
$incoming_id = isset($_GET['incoming_id']) ? filter_var($_GET['incoming_id'], FILTER_VALIDATE_INT) : 0;
$outgoing_id = $_SESSION['unique_id'];

if (!$incoming_id) {
    http_response_code(400);
    echo "data: " . json_encode(['error' => 'Invalid user ID']) . "\n\n";
    exit;
}

// Verify the user exists
$user = get_user_by_id($conn, $incoming_id);
if (!$user) {
    http_response_code(404);
    echo "data: " . json_encode(['error' => 'User not found']) . "\n\n";
    exit;
}

// Set SSE headers
set_sse_headers();

// Send initial connection confirmation
echo "event: connected\n";
echo "data: " . json_encode(['message' => 'SSE connection established', 'timestamp' => time()]) . "\n\n";
flush();

// Track last message ID for incremental updates
$last_msg_id = isset($_GET['last_msg_id']) ? intval($_GET['last_msg_id']) : 0;
$heartbeat_interval = 30; // seconds
$last_heartbeat = time();

// Main SSE loop
while (true) {
    // Check connection still alive
    if (connection_aborted()) {
        break;
    }
    
    // Send heartbeat every 30 seconds to keep connection alive
    if (time() - $last_heartbeat >= $heartbeat_interval) {
        echo "event: heartbeat\n";
        echo "data: " . json_encode(['timestamp' => time()]) . "\n\n";
        flush();
        $last_heartbeat = time();
    }
    
    // Fetch new messages
    $sql = "SELECT m.*, 
            u_outgoing.fname as sender_fname, 
            u_outgoing.lname as sender_lname,
            u_outgoing.img as sender_img
            FROM messages m
            JOIN users u_outgoing ON m.outgoing_msg_id = u_outgoing.unique_id
            WHERE ((m.outgoing_msg_id = ? AND m.incoming_msg_id = ?) 
               OR (m.outgoing_msg_id = ? AND m.incoming_msg_id = ?))
            AND m.msg_id > ?
            ORDER BY m.msg_id ASC";
    
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("iiiii", $outgoing_id, $incoming_id, $incoming_id, $outgoing_id, $last_msg_id);
    $stmt->execute();
    $result = $stmt->get_result();
    
    $messages = [];
    while ($row = $result->fetch_assoc()) {
        $messages[] = [
            'msg_id' => $row['msg_id'],
            'incoming_msg_id' => $row['incoming_msg_id'],
            'outgoing_msg_id' => $row['outgoing_msg_id'],
            'msg' => escape_html($row['msg']),
            'created_at' => $row['created_at'],
            'is_read' => $row['is_read'],
            'sender_fname' => escape_html($row['sender_fname']),
            'sender_lname' => escape_html($row['sender_lname']),
            'sender_img' => $row['sender_img']
        ];
        $last_msg_id = max($last_msg_id, $row['msg_id']);
    }
    $stmt->close();
    
    // Send messages if any
    if (!empty($messages)) {
        echo "event: message\n";
        echo "data: " . json_encode(['messages' => $messages, 'count' => count($messages)]) . "\n\n";
        flush();
        
        // Mark messages as read
        $update_stmt = $conn->prepare("UPDATE messages SET is_read = 1 WHERE incoming_msg_id = ? AND outgoing_msg_id = ? AND is_read = 0");
        $update_stmt->bind_param("ii", $outgoing_id, $incoming_id);
        $update_stmt->execute();
        $update_stmt->close();
    }
    
    // Small delay to prevent CPU spinning
    usleep(500000); // 500ms
}

$conn->close();
?>
