<?php
session_start();
require 'connect.php';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $login = $_POST['username'];
    $password = $_POST['password'];

    $stmt = $conn->prepare("SELECT id, login, password_hash, aes_key FROM users WHERE login = ?");
    $stmt->execute([$login]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($user && password_verify($password, $user['password_hash'])) {
        $aesKey = openssl_decrypt($user['aes_key'], 'AES-256-CBC', $password, 0, substr(hash('sha256', $password), 0, 16));
        if ($aesKey !== false) {
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['login'];
            $_SESSION['aes_key'] = $aesKey;
            header("Location: index.php");
            exit;
        }
    }
    $error = "Invalid login, password, or AES key!";
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <title>Login</title>
</head>
<body>
    <h2 style="text-align: center;">Login</h2>
    <form method="post" action="login.php" style="text-align: center;">
        <?php if (isset($error)) echo "<p style='color:red;'>$error</p>"; ?>
        <p>Username: <input type="text" name="username" required></p>
        <p>Password: <input type="password" name="password" required></p>
        <p>
            <input type="submit" value="Login">
        </p>
        <p>Don't have an account? <a href="register.php">Register</a></p>
    </form>
</body>
</html>

