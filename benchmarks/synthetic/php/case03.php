<?php
$conn = mysqli_connect("localhost", "app", getenv("DB_PASS"), "shop");
mysqli_set_charset($conn, "utf8mb4");

$id = mysqli_real_escape_string($conn, $_POST['id']);
$res = mysqli_query($conn, "SELECT email FROM users WHERE id = $id");
$row = mysqli_fetch_assoc($res);
echo htmlspecialchars($row['email'] ?? '', ENT_QUOTES, 'UTF-8');
