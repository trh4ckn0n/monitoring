<?php
require __DIR__ . '/utils.php';
start_secure_session();
session_destroy();
header('Location: /login.php');
