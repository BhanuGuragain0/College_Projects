<?php
// ============================================================================
// USER SEARCH - SECURITY HARDENED
// ============================================================================

session_start();
include_once "config.php";
include_once "security.php";

// Require login
require_login();

// Only accept POST requests
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    send_response('error', 'Invalid request method');
}

$outgoing_id = $_SESSION['unique_id'];

// Validate and sanitize search term
$search_term = validate_input($_POST['searchTerm'] ?? '');

if (empty($search_term)) {
    send_response('error', 'Search term cannot be empty');
}

// Limit search term length to prevent performance issues
if (strlen($search_term) > 100) {
    send_response('error', 'Search term is too long (max 100 characters)');
}

// Use prepared statement to prevent SQL injection
$stmt = $conn->prepare("SELECT user_id, unique_id, fname, lname, email, img, status FROM users 
                        WHERE unique_id != ? 
                        AND (fname LIKE CONCAT('%', ?, '%') 
                             OR lname LIKE CONCAT('%', ?, '%') 
                             OR email LIKE CONCAT('%', ?, '%'))
                        LIMIT 50");

if ($stmt === false) {
    log_security_event('SEARCH_ERROR', "Database prepare error: " . $conn->error, 'ERROR');
    send_response('error', 'Database error occurred');
}

$stmt->bind_param("isss", $outgoing_id, $search_term, $search_term, $search_term);

if (!$stmt->execute()) {
    log_security_event('SEARCH_ERROR', "Database execute error: " . $stmt->error, 'ERROR');
    send_response('error', 'Search failed');
}

$result = $stmt->get_result();
$output = "";

if ($result->num_rows > 0) {
    $query = $result;
    include_once "data.php";
} else {
    $output = escape_html('No user found related to your search term: ' . $search_term);
}

header('Content-Type: text/html; charset=utf-8');
echo $output;

$stmt->close();
$conn->close();
?>
