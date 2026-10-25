<?php
$conn = mysqli_connect("localhost", "app", getenv("DB_PASS"), "shop");
mysqli_set_charset($conn, "utf8mb4");

function find_user($conn, $email) {
    return mysqli_query($conn, "SELECT id FROM users WHERE email = '$email'");
}

$res = find_user($conn, $_POST['email']);
echo mysqli_num_rows($res) > 0 ? "found" : "missing";
