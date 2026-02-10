<?php
// Database credentials
$servername = "localhost";
$username = "root";
$password = "";
$dbname = "chat_app";

// Create connection
$conn = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Enable error reporting
mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $fname = htmlspecialchars($_POST['name']); // Assuming 'name' in the form corresponds to first name
    $email = htmlspecialchars($_POST['email']);

    // Prepare and execute the query to check user
    $query = "SELECT email FROM users WHERE fname = ? AND email = ?";
    $stmt = $conn->prepare($query);

    if (!$stmt) {
        die("Prepare failed: " . $conn->error . " Query: " . $query);
    }

    $stmt->bind_param("ss", $fname, $email);
    $stmt->execute();
    $stmt->store_result();

    if ($stmt->num_rows > 0) {
        // Generate a unique reset token
        $reset_token = bin2hex(random_bytes(32));
        $reset_expiry = date("Y-m-d H:i:s", strtotime('+1 hour'));

        // Prepare and execute the query to insert reset token
        $query = "INSERT INTO password_resets (email, token, expires_at) VALUES (?, ?, ?)";
        $stmt = $conn->prepare($query);

        if (!$stmt) {
            die("Prepare failed: " . $conn->error . " Query: " . $query);
        }

        $stmt->bind_param("sss", $email, $reset_token, $reset_expiry);
        if (!$stmt->execute()) {
            die("Execute failed: " . $stmt->error);
        }

        // Create the reset link
        $reset_link = "http://yourdomain.com/reset-password.php?token=" . $reset_token;

        // Send the reset link via email
        $subject = "Password Reset Request";
        $message = "Hello, click the link below to reset your password:\n\n$reset_link\n\nIf you did not request this, please ignore this email.";
        $headers = "From: no-reply@yourdomain.com";

        if (mail($email, $subject, $message, $headers)) {
            echo "An email with a password reset link has been sent to your email address.";
        } else {
            echo "Failed to send the email. Please try again later.";
        }
    } else {
        echo "No user found with the provided first name and email.";
    }

    $stmt->close();
    $conn->close();
} else {
    header('Location: ../forgot-password.html');
    exit();
}
?>
