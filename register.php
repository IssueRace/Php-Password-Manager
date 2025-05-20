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
<HTML>
    <HEAD>
        <TITLE> Register </TITLE>
        <META charset="UTF-8">
    </HEAD>
    <BODY>
        <p ALIGN=center> Register: </p>
        <FORM METHOD="post" ACTION="register.php">
            Username: <INPUT TYPE="text" NAME="username" required><br>
            Password: <INPUT TYPE="password" NAME="password" required><br>
            <INPUT TYPE="submit" VALUE="Register">
            <INPUT TYPE="reset" VALUE="Reset">
        </FORM>
        <p>Already have an account? <a href="form.html">Login</a></p>
    </BODY>
</HTML>