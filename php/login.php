<?php
session_start();
include_once "config.php"; // Ensure this file contains the correct MySQL connection

// Function to validate input and prevent SQL injection
function validate_input($data) {
    return htmlspecialchars(stripslashes(trim($data)));
}

// Function to log errors
function log_error($message) {
    error_log($message, 3, 'errors.log');
}

// Validate and sanitize inputs
$email = validate_input($_POST['email']);
$password = validate_input($_POST['password']);

if (!empty($email) && !empty($password)) {
    if (filter_var($email, FILTER_VALIDATE_EMAIL)) {
        // Use prepared statements to prevent SQL injection
        $stmt = $conn->prepare("SELECT * FROM users WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows > 0) {
            $row = $result->fetch_assoc();
            $enc_pass = $row['password'];

            if (password_verify($password, $enc_pass)) {
                $status = "Active now";
                $stmt2 = $conn->prepare("UPDATE users SET status = ? WHERE unique_id = ?");
                $stmt2->bind_param("si", $status, $row['unique_id']);
                if ($stmt2->execute()) {
                    $_SESSION['unique_id'] = $row['unique_id'];
                    echo "success";
                } else {
                    log_error("Failed to update status: " . $conn->error);
                    echo "Something went wrong. Please try again!";
                }
                $stmt2->close();
            } else {
                echo "Email or Password is Incorrect!";
            }
        } else {
            echo "$email - This email does not exist!";
        }
        $stmt->close();
    } else {
        echo "$email is not a valid email!";
    }
} else {
    echo "All input fields are required!";
}

// Close the database connection
$conn->close();
?>
