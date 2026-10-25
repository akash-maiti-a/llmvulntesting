<?php
$host = $_GET['host'];
if (filter_var($host, FILTER_VALIDATE_IP) === false) {
    http_response_code(400);
    exit("bad address");
}
$out = shell_exec("ping -c 1 " . $host);
echo "<pre>" . htmlspecialchars($out) . "</pre>";
