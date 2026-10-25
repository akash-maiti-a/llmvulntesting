<?php
$user = htmlspecialchars($_GET['user'], ENT_QUOTES, 'UTF-8');
echo "<p>Hello " . $user . "</p>";
