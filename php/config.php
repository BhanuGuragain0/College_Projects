<?php
// Database credentials
$servername = "localhost";  // Change this if your database server is different
$username = "root";         // Your database username
$password = "";             // Your database password
$dbname = "chat_app";        // Your database name

// Create connection
$conn = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}
?>
