<?php
session_start();

function log_message($message) {
    $log_file = 'log.txt';
    $current_time = date('Y-m-d H:i:s');
    $log_message = $current_time . ' - ' . $message . "\n";
    file_put_contents($log_file, $log_message, FILE_APPEND);
}

if (isset($_SESSION['unique_id'])) {
    include_once "config.php";

    $outgoing_id = $_SESSION['unique_id'];
    $incoming_id = filter_var($_POST['incoming_id'], FILTER_VALIDATE_INT);
    $message = htmlspecialchars($_POST['message'], ENT_QUOTES, 'UTF-8');

    if ($incoming_id === false) {
        log_message("Invalid incoming_id: " . $_POST['incoming_id']);
        die("Invalid incoming ID.");
    }

    if (!empty($message)) {
        $sql = $conn->prepare("INSERT INTO messages (incoming_msg_id, outgoing_msg_id, msg) VALUES (?, ?, ?)");
        $sql->bind_param("iis", $incoming_id, $outgoing_id, $message);
        
        if ($sql->execute()) {
            log_message("Message from $outgoing_id to $incoming_id sent successfully.");
            echo "Message sent successfully!";
        } else {
            log_message("Failed to send message from $outgoing_id to $incoming_id: " . $sql->error);
            echo "Message sending failed!";
        }
    } else {
        log_message("Empty message attempted to be sent from $outgoing_id to $incoming_id.");
        echo "Message cannot be empty.";
    }
} else {
    log_message("Unauthorized access attempt.");
    header("Location: ../login.php");
    exit();
}
?>
