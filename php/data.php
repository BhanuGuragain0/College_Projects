<?php
// ============================================================================
// CYBER CHAT APP - FORMAT USER LIST DATA
// Helper to generate user list HTML
// ============================================================================

if (!isset($query) || !isset($outgoing_id) || !isset($conn)) {
    die('Invalid context for data.php');
}

$output = "";

while ($row = $query->fetch_assoc()) {
    if (!isset($row['unique_id']) || !is_numeric($row['unique_id'])) {
        continue;
    }
    
    // Get last message
    $stmt = $conn->prepare("SELECT msg, outgoing_msg_id, created_at FROM messages 
                            WHERE (incoming_msg_id = ? AND outgoing_msg_id = ?) 
                               OR (incoming_msg_id = ? AND outgoing_msg_id = ?)
                            ORDER BY msg_id DESC LIMIT 1");
    
    if ($stmt === false) {
        continue;
    }
    
    $stmt->bind_param("iiii", $row['unique_id'], $outgoing_id, $outgoing_id, $row['unique_id']);
    $stmt->execute();
    $result_msg = $stmt->get_result();
    $row2 = $result_msg->fetch_assoc();
    $stmt->close();
    
    if ($result_msg->num_rows > 0 && isset($row2['msg'])) {
        $result = $row2['msg'];
        $msg_time = isset($row2['created_at']) ? format_timestamp($row2['created_at']) : '';
    } else {
        $result = "Click to start chatting";
        $msg_time = '';
    }
    
    if (strlen($result) > 28) {
        $msg = substr($result, 0, 28) . '...';
    } else {
        $msg = $result;
    }
    
    $you = "";
    if ($result_msg->num_rows > 0 && isset($row2['outgoing_msg_id']) && $outgoing_id == $row2['outgoing_msg_id']) {
        $you = "You: ";
    }
    
    $offline = ($row['status'] == "Offline now") ? "offline" : "";
    $status_text = ($row['status'] == "Active now") ? "online" : "offline";
    
    $user_id = escape_html($row['unique_id']);
    $fname = escape_html($row['fname']);
    $lname = escape_html($row['lname']);
    $img = escape_html($row['img']);
    $msg = escape_html($you . $msg);
    
    $output .= '<a href="chat.php?user_id=' . $user_id . '">
                    <div class="content">
                        <img src="php/images/' . $img . '" alt="' . $fname . ' ' . $lname . '">
                        <div class="details">
                            <span>' . $fname . ' ' . $lname . '</span>
                            <p>' . $msg . '</p>
                        </div>
                    </div>
                    <div class="status-dot ' . $offline . '" title="' . $status_text . '"><i class="fas fa-circle"></i></div>
                </a>';
}
?>
