<?php
$prefs = json_decode($_COOKIE['prefs'] ?? '[]', true);
echo is_array($prefs) ? count($prefs) : 0;
