<?php
session_start();
require 'connect.php';

if (!isset($_SESSION['user_id']) || !isset($_SESSION['aes_key']) || !isset($_SESSION['username'])) {
    header("Location: login.php");
    exit;
}

if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['add_password'])) {
    $serviceName = $_POST['service_name'];
    $password = $_POST['password'];
    $encryptedPassword = openssl_encrypt($password, 'AES-256-CBC', $_SESSION['aes_key'], 0, substr(hash('sha256', $_SESSION['aes_key']), 0, 16));

    try {
        $stmt = $conn->prepare("INSERT INTO passwords (user_id, service_name, encrypted_password) VALUES (?, ?, ?)");
        $stmt->execute([$_SESSION['user_id'], $serviceName, $encryptedPassword]);
    } catch (PDOException $e) {
        $error = "Error adding password: " . $e->getMessage();
    }
    header("Location: index.php");
    exit;
}

if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['delete_password'])) {
    $passwordId = $_POST['password_id'];
    try {
        $stmt = $conn->prepare("DELETE FROM passwords WHERE id = ? AND user_id = ?");
        $stmt->execute([$passwordId, $_SESSION['user_id']]);
    } catch (PDOException $e) {
        $error = "Error deleting password: " . $e->getMessage();
    }
    header("Location: index.php");
    exit;
}

$stmt = $conn->prepare("SELECT id, service_name, encrypted_password, created_at FROM passwords WHERE user_id = ?");
$stmt->execute([$_SESSION['user_id']]);
$passwords = $stmt->fetchAll(PDO::FETCH_ASSOC);

foreach ($passwords as &$password) {
    $decrypted = openssl_decrypt($password['encrypted_password'], 'AES-256-CBC', $_SESSION['aes_key'], 0, substr(hash('sha256', $_SESSION['aes_key']), 0, 16));
    $password['password'] = $decrypted !== false ? $decrypted : 'Decryption failed';
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Password Manager</title>
</head>
<body>
    <h2>Welcome, <?php echo htmlspecialchars($_SESSION['username']); ?>!</h2>
    <p><a href="logout.php">Logout</a></p>
    <?php if (isset($error)) echo "<p style='color:red;'>$error</p>"; ?>

    <h3>Add Password</h3>
    <form method="post">
        <p>Service: <input type="text" name="service_name" required></p>
        <p>Password: <input type="text" name="password" required></p>
        <input type="submit" name="add_password" value="Save">
    </form>

    <h3>Your Passwords</h3>
    <table border="1">
        <tr>
            <th>Service</th>
            <th>Password</th>
            <th>Created At</th>
            <th>Actions</th>
        </tr>
        <?php if (empty($passwords)) { ?>
            <tr><td colspan="4">No passwords found</td></tr>
        <?php } else { ?>
            <?php foreach ($passwords as $password) { ?>
                <tr>
                    <td><?php echo htmlspecialchars($password['service_name']); ?></td>
                    <td><?php echo htmlspecialchars($password['password']); ?></td>
                    <td><?php echo $password['created_at']; ?></td>
                    <td>
                        <form method="post" style="display:inline;">
                            <input type="hidden" name="password_id" value="<?php echo $password['id']; ?>">
                            <input type="submit" name="delete_password" value="Delete">
                        </form>
                    </td>
                </tr>
            <?php } ?>
        <?php } ?>
    </table>
</body>
</html>