<?php
    session_start();
    include_once "config.php";
    include_once "security.php";
    
    // Require login
    require_login();
    
    $outgoing_id = $_SESSION['unique_id'];
    
    // Validate user ID is numeric
    if (!is_numeric($outgoing_id)) {
        send_response('error', 'Invalid user ID');
    }
    
    // Use prepared statement to prevent SQL injection
    $stmt = $conn->prepare("SELECT user_id, unique_id, fname, lname, email, img, status 
                            FROM users 
                            WHERE unique_id != ? 
                            ORDER BY status DESC, user_id DESC 
                            LIMIT 100");
    
    if ($stmt === false) {
        log_security_event('USERS_ERROR', "Database prepare error: " . $conn->error, 'ERROR');
        send_response('error', 'Database error occurred');
    }
    
    $stmt->bind_param("i", $outgoing_id);
    
    if (!$stmt->execute()) {
        log_security_event('USERS_ERROR', "Database execute error: " . $stmt->error, 'ERROR');
        send_response('error', 'Failed to fetch users');
    }
    
    $result = $stmt->get_result();
    $output = "";
    
    if ($result->num_rows == 0) {
        $output = escape_html('No users are available to chat');
    } else {
        $query = $result;
        include_once "data.php";
    }
    
    header('Content-Type: text/html; charset=utf-8');
    echo $output;
    
    $stmt->close();
    $conn->close();
?>