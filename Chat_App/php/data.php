<?php
// ============================================================================
// FORMAT USER LIST DATA - SECURITY HARDENED
// ============================================================================

if (!isset($query) || !isset($outgoing_id) || !isset($conn)) {
    die('Invalid context for data.php');
}

$output = "";

while ($row = $query->fetch_assoc()) {
    if (!isset($row['unique_id']) || !is_numeric($row['unique_id'])) {
        continue;
    }
    
    $stmt = $conn->prepare("SELECT msg, outgoing_msg_id FROM messages 
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
    } else {
        $result = "No message available";
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
    $hid_me = ($outgoing_id == $row['unique_id']) ? "hide" : "";
    
    $output .= '<a href="chat.php?user_id=' . escape_html($row['unique_id']) . '">
                    <div class="content">
                    <img src="php/images/' . escape_html($row['img']) . '" alt="' . escape_html($row['fname']) . '">
                    <div class="details">
                        <span>' . escape_html($row['fname']) . " " . escape_html($row['lname']) . '</span>
                        <p>' . escape_html($you . $msg) . '</p>
                    </div>
                    </div>
                    <div class="status-dot ' . $offline . '"><i class="fas fa-circle"></i></div>
                </a>';
}
?>

    
    $user_id = escape_html($row['unique_id']);
    $fname = escape_html($row['fname']);
    $lname = escape_html($row['lname']);
    $img = escape_html($row['img']);
    $msg = escape_html($msg);
    $you = escape_html($you);
    
    $output .= '<a href="chat.php?user_id=' . $user_id . '">'
                    <div class="content">
                    <img src="php/images/' . $img . '" alt="' . $fname . ' ' . $lname . '">
                    <div class="details">
                        <span>' . $fname . " " . $lname . '</span>
                        <p>' . $you . $msg . '</p>
                    </div>
                    </div>
                    <div class="status-dot ' . $offline . '"><i class="fas fa-circle"></i></div>
                </a>';'
}
?>
