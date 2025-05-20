<?php
session_start();
include "connect.php";

if (!isset($_SESSION['user_id'])) {
    header("Location: form.html");
    exit;
}

if (isset($_GET['action']) && $_GET['action'] == 'register' && $_SERVER['REQUEST_METHOD'] == 'POST') {
    $login = $_POST['username'];
    $password = password_hash($_POST['password'], PASSWORD_DEFAULT);
    $stmt = $conn->prepare("INSERT INTO book (login, password) VALUES (?, ?)");
    $stmt->execute([$login, $password]);
    header("Location: list.php");
    exit;
}

if (isset($_GET['action']) && $_GET['action'] == 'delete_user' && isset($_GET['id'])) {
    $id = $_GET['id'];
    $stmt = $conn->prepare("DELETE FROM book WHERE id = ?");
    $stmt->execute([$id]);
    header("Location: list.php");
    exit;
}

if (isset($_GET['action']) && $_GET['action'] == 'change_user' && $_SERVER['REQUEST_METHOD'] == 'POST') {
    $id = $_POST['id'];
    $login = $_POST['username'];
    $password = !empty($_POST['password']) ? password_hash($_POST['password'], PASSWORD_DEFAULT) : null;

    if ($password) {
        $stmt = $conn->prepare("UPDATE book SET login = ?, password = ? WHERE id = ?");
        $stmt->execute([$login, $password, $id]);
    } else {
        $stmt = $conn->prepare("UPDATE book SET login = ? WHERE id = ?");
        $stmt->execute([$login, $id]);
    }
    header("Location: list.php");
    exit;
}

if (isset($_GET['action']) && $_GET['action'] == 'change_user' && isset($_GET['id'])) {
    $id = $_GET['id'];
    $stmt = $conn->prepare("SELECT login FROM book WHERE id = ?");
    $stmt->execute([$id]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    echo '<h2>Edit User</h2>';
    echo '<form method="post" action="list.php?action=change_user">';
    echo '<input type="hidden" name="id" value="' . $id . '">';
    echo 'Username: <input type="text" name="username" value="' . htmlspecialchars($user['login']) . '" required><br>';
    echo 'Password: <input type="password" name="password"><br>';
    echo '<input type="submit" value="Update">';
    echo '<input type="reset" value="Reset">';
    echo '</form>';
    echo '<a href="list.php">Back to List</a>';
    exit;
}

echo "Welcome, " . htmlspecialchars($_SESSION['username']) . " | <a href='logout.php'>Logout</a><br><br>";

$sql = "SELECT id, login FROM book";
$data = $conn->query($sql)->fetchAll();

$sql_count = "SELECT count(id) as kiekis FROM book";
$count = $conn->query($sql_count)->fetchColumn();

echo "Found users: $count<br><br>";

echo '<table border="1" cellpadding="8" cellspacing="0">';
echo '<tr>
        <th>ID</th>
        <th>Username</th>
        <th>Actions</th>
      </tr>';

foreach ($data as $row) {
    $id = $row['id'];
    $login = htmlspecialchars($row['login']);

    echo '<tr>';
    echo "<td>$id</td>";
    echo "<td>$login</td>";
    echo "<td>
            <a href='list.php?action=delete_user&id=$id'>Remove</a> |
            <a href='list.php?action=change_user&id=$id'>Change</a>
          </td>";
    echo '</tr>';
}

echo '</table>';

echo '<br><h2>Register New User</h2>';
echo '<form method="post" action="list.php?action=register">';
echo 'Username: <input type="text" name="username" required><br>';
echo 'Password: <input type="password" name="password" required><br>';
echo '<input type="submit" value="Register">';
echo '<input type="reset" value="Reset">';
echo '</form>';
?>