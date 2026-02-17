<?php
// ============================================================================
// CYBER CHAT APP - USER SEARCH ENDPOINT
// ============================================================================

session_start();
include_once "config.php";
include_once "security.php";

header('Content-Type: application/json');

// Require login
require_login();

// Get and validate search term
$outgoing_id = $_SESSION['unique_id'];
$search_term = validate_input($_GET['search'] ?? '');

if (empty($search_term)) {
    send_response('error', 'Search term cannot be empty');
}

// Limit search term length
if (strlen($search_term) > 100) {
    send_response('error', 'Search term is too long (max 100 characters)');
}

$search_like = "%$search_term%";

// Search users
$stmt = $conn->prepare("SELECT user_id, unique_id, fname, lname, email, img, status, last_seen 
                        FROM users 
                        WHERE unique_id != ? 
                        AND (fname LIKE ? OR lname LIKE ? OR email LIKE ?)
                        ORDER BY status DESC, user_id DESC 
                        LIMIT 50");

if ($stmt === false) {
    log_security_event('SEARCH_ERROR', "Database prepare error: " . $conn->error, 'ERROR');
    send_response('error', 'Database error occurred');
}

$stmt->bind_param("isss", $outgoing_id, $search_like, $search_like, $search_like);

if (!$stmt->execute()) {
    log_security_event('SEARCH_ERROR', "Database execute error: " . $stmt->error, 'ERROR');
    send_response('error', 'Search failed');
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

send_response('success', 'Search completed', ['users' => $users, 'count' => count($users)]);
?>
