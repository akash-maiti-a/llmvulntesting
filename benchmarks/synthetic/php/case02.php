<?php
$conn = mysqli_connect("localhost", "app", getenv("DB_PASS"), "shop");
mysqli_set_charset($conn, "utf8mb4");

$stmt = mysqli_prepare($conn, "SELECT id, price FROM products WHERE name = ?");
mysqli_stmt_bind_param($stmt, "s", $_GET['name']);
mysqli_stmt_execute($stmt);
$res = mysqli_stmt_get_result($stmt);
while ($row = mysqli_fetch_assoc($res)) {
    echo (int) $row['id'] . "\n";
}
