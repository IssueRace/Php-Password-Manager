<?php
session_start();
require 'connect.php';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $login = $_POST['username'];
    $password = $_POST['password'];

    $aesKey = openssl_random_pseudo_bytes(32);
    $encryptedAesKey = openssl_encrypt($aesKey, 'AES-256-CBC', $password, 0, substr(hash('sha256', $password), 0, 16));
    $passwordHash = password_hash($password, PASSWORD_DEFAULT);

    try {
        $stmt = $conn->prepare("INSERT INTO users (login, password_hash, aes_key) VALUES (?, ?, ?)");
        $stmt->execute([$login, $passwordHash, $encryptedAesKey]);
        header("Location: login.php");
        exit;
    } catch (PDOException $e) {
        $error = "Registration error: " . $e->getMessage();
    }
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
        <?php if (isset($error)) echo "<p style='color:red;'>$error</p>"; ?>
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