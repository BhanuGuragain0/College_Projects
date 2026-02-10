<?php
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // Sanitize inputs
    $token = htmlspecialchars($_POST['token']);
    $new_password = htmlspecialchars($_POST['new_password']);

    // Validate the token and update the password
    $conn = new mysqli('localhost', 'username', 'password', 'database');

    if ($conn->connect_error) {
        die("Connection failed: " . $conn->connect_error);
    }

    $stmt = $conn->prepare("SELECT email FROM password_resets WHERE token = ? AND expires_at > NOW()");
    $stmt->bind_param("s", $token);
    $stmt->execute();
    $stmt->store_result();

    if ($stmt->num_rows > 0) {
        $stmt->bind_result($email);
        $stmt->fetch();

        // Validate password strength (example: minimum 8 characters)
        if (strlen($new_password) < 8) {
            echo "Password must be at least 8 characters long.";
            exit();
        }

        // Update the password (assuming you have a `users` table)
        $hashed_password = password_hash($new_password, PASSWORD_DEFAULT);
        $update_stmt = $conn->prepare("UPDATE users SET password = ? WHERE email = ?");
        $update_stmt->bind_param("ss", $hashed_password, $email);

        if ($update_stmt->execute()) {
            // Delete the token after successful password reset
            $delete_stmt = $conn->prepare("DELETE FROM password_resets WHERE token = ?");
            $delete_stmt->bind_param("s", $token);
            $delete_stmt->execute();
            $delete_stmt->close();

            echo "Password has been reset successfully.";
        } else {
            echo "Failed to reset password. Please try again.";
        }

        $update_stmt->close();
    } else {
        echo "Invalid or expired token.";
    }

    $stmt->close();
    $conn->close();
} else {
    if (isset($_GET['token'])) {
        $token = htmlspecialchars($_GET['token']);
        ?>
        <form method="POST" action="reset_password.php">
            <input type="hidden" name="token" value="<?php echo htmlspecialchars($token); ?>">
            <label for="new_password">New Password</label>
            <input type="password" name="new_password" required>
            <button type="submit">Reset Password</button>
        </form>
        <?php
    } else {
        echo "Invalid request.";
    }
}
?>
