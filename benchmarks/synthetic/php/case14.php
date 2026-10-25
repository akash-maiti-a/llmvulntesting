<?php
$prefs = unserialize($_COOKIE['prefs']);
echo is_array($prefs) ? count($prefs) : 0;
