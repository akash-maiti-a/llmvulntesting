<?php
$host = $_GET['host'];
$out = shell_exec("ping -c 1 " . $host);
echo "<pre>" . htmlspecialchars($out) . "</pre>";
