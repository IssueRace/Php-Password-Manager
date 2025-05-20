<?php
require 'connect.php';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $login = $_POST['username'];
    $password = password_hash($_POST['password'], PASSWORD_DEFAULT);

    $stmt = $conn->prepare("INSERT INTO book (login, password) VALUES (?, ?)");
    $stmt->execute([$login, $password]);

    header("Location: form.html");
    exit;

}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Register</title>
</head>
<body>
    <h2 style="text-align: center;">Register</h2>
    <form method="post" action="register.php" style="text-align: center;">
        <p>Username: <input type="text" name="username" required></p>
        <p>Password: <input type="password" name="password" required></p>
        <p>
            <input type="submit" value="Register">
            <input type="reset" value="Reset">
        </p>
        <p>Already have an account? <a href="login.php">Login</a></p>
    </form>
</body>
</html>
