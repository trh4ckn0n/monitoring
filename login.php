<?php
require __DIR__ . '/utils.php';
start_secure_session();
$c = cfg();

$error = null;
if ($_SERVER['REQUEST_METHOD']==='POST') {
    $email = trim($_POST['email'] ?? '');
    $pass  = $_POST['password'] ?? '';
    if (hash_equals($c['AUTH_EMAIL'], $email) && password_verify($pass, $c['AUTH_PASS_HASH'])) {
        $_SESSION['user'] = ['email'=>$email, 'ip'=>client_ip(), 'ts'=>time()];
        header('Location: /index.php'); exit;
    } else {
        $error = "Identifiants invalides";
    }
}
?>
<!doctype html><meta charset="utf-8">
<link rel="stylesheet" href="https://unpkg.com/@picocss/pico@2.0.6/css/pico.min.css">
<main class="container">
  <h2>Connexion NetMon</h2>
  <?php if($error): ?><p style="color:#c00"><?=$error?></p><?php endif; ?>
  <form method="post">
    <label>E‑mail <input type="email" name="email" required></label>
    <label>Mot de passe <input type="password" name="password" required></label>
    <button type="submit">Se connecter</button>
  </form>
</main>
