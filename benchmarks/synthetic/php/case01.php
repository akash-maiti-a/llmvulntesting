<?php
$conn = mysqli_connect("localhost", "app", getenv("DB_PASS"), "shop");
mysqli_set_charset($conn, "utf8mb4");

$name = $_GET['name'];
$sql = "SELECT id, price FROM products WHERE name = '" . $name . "'";
$res = mysqli_query($conn, $sql);
while ($row = mysqli_fetch_assoc($res)) {
    echo (int) $row['id'] . "\n";
}
