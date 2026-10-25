<?php
$conn = mysqli_connect("localhost", "app", getenv("DB_PASS"), "shop");
mysqli_set_charset($conn, "utf8mb4");

$name = mysqli_real_escape_string($conn, $_POST['name']);
$res = mysqli_query($conn, "SELECT email FROM users WHERE name = '$name'");
$row = mysqli_fetch_assoc($res);
echo htmlspecialchars($row['email'] ?? '', ENT_QUOTES, 'UTF-8');
