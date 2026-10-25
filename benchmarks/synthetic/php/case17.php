<?php
$next = $_GET['next'] ?? '/';
if (!preg_match('#^/[a-z0-9/_-]*$#i', $next) || str_starts_with($next, '//')) {
    $next = '/';
}
header("Location: " . $next);
exit;
