<?php
require_once __DIR__ . '/../src/helpers.php';

$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';

    // Parameterized lookup by username only; the password is verified in PHP
    // against the stored hash. User input never becomes part of the SQL text.
    $stmt = db()->prepare('SELECT * FROM users WHERE username = ?');
    $stmt->execute([$username]);
    $row = $stmt->fetch();

    if ($row && password_verify($password, $row['password'])) {
        // New session id on privilege change to prevent session fixation.
        session_regenerate_id(true);
        $_SESSION['user_id'] = (int) $row['id'];
        header('Location: index.php');
        exit;
    }

    // Generic message: do not reveal whether the username exists, and never
    // echo the query or the raw exception back to the client.
    $error = 'Invalid username or password.';
}

render_header('Log in');
?>
<div class="row justify-content-center">
    <div class="col-md-5">
        <h1 class="h4 mb-3">Log in</h1>
        <?php if ($error): ?>
            <div class="alert alert-danger"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>
        <form method="post" class="card card-body shadow-sm">
            <div class="mb-3">
                <label class="form-label">Username</label>
                <input name="username" class="form-control" autofocus>
            </div>
            <div class="mb-3">
                <label class="form-label">Password</label>
                <input name="password" type="password" class="form-control">
            </div>
            <button class="btn btn-primary">Log in</button>
            <p class="small mt-3 mb-0">No account? <a href="register.php">Register</a>.</p>
        </form>
    </div>
</div>
<?php render_footer(); ?>
