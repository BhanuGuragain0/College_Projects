<?php
// ============================================================================
// CYBER CHAT APP - USERS LIST ENDPOINT
// Returns list of all users except current user
// ============================================================================

session_start();
include_once "config.php";
include_once "security.php";

header('Content-Type: application/json');

// Require login
require_login();

$outgoing_id = $_SESSION['unique_id'];

// Get optional search parameter
$search = isset($_GET['search']) ? validate_input($_GET['search']) : '';

// Build query
if (!empty($search)) {
    $search_term = "%$search%";
    $stmt = $conn->prepare("SELECT user_id, unique_id, fname, lname, email, img, status, last_seen 
                            FROM users 
                            WHERE unique_id != ? 
                            AND (fname LIKE ? OR lname LIKE ? OR email LIKE ?)
                            ORDER BY status DESC, user_id DESC 
                            LIMIT 100");
    $stmt->bind_param("isss", $outgoing_id, $search_term, $search_term, $search_term);
} else {
    $stmt = $conn->prepare("SELECT user_id, unique_id, fname, lname, email, img, status, last_seen 
                            FROM users 
                            WHERE unique_id != ? 
                            ORDER BY status DESC, user_id DESC 
                            LIMIT 100");
    $stmt->bind_param("i", $outgoing_id);
}

if ($stmt === false) {
    log_security_event('USERS_ERROR', "Database prepare error: " . $conn->error, 'ERROR');
    send_response('error', 'Database error occurred');
}

if (!$stmt->execute()) {
    log_security_event('USERS_ERROR', "Database execute error: " . $stmt->error, 'ERROR');
    send_response('error', 'Failed to fetch users');
}

$result = $stmt->get_result();
$users = [];

while ($row = $result->fetch_assoc()) {
    $users[] = [
        'user_id' => $row['user_id'],
        'unique_id' => $row['unique_id'],
        'fname' => escape_html($row['fname']),
        'lname' => escape_html($row['lname']),
        'email' => escape_html($row['email']),
        'img' => $row['img'],
        'status' => $row['status'],
        'last_seen' => $row['last_seen'],
        'formatted_time' => $row['last_seen'] ? format_timestamp($row['last_seen']) : 'Never'
    ];
}

$stmt->close();
$conn->close();

send_response('success', 'Users fetched successfully', ['users' => $users, 'count' => count($users)]);
?>