<?php
require_once __DIR__ . '/../src/helpers.php';
require_login();

$id = $_GET['id'] ?? '';

// Only delete the topic if the current user owns it (or is an admin).
$stmt = db()->prepare('SELECT user_id FROM topics WHERE id = ?');
$stmt->execute([$id]);
$topic = $stmt->fetch();

if ($topic && can_modify((int) $topic['user_id'])) {
    $del = db()->prepare('DELETE FROM topics WHERE id = ?');
    $del->execute([$id]);
}

header('Location: index.php');
exit;
