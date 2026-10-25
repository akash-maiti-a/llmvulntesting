<?php
$page = $_GET['page'] ?? 'home';
$allowed = ['home', 'about', 'contact'];
if (!in_array($page, $allowed, true)) {
    $page = 'home';
}
include("pages/" . $page . ".php");
