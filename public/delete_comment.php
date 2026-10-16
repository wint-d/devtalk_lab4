<?php
require_once __DIR__ . '/../src/helpers.php';
require_login();

$id      = $_GET['id'] ?? '';
$topicId = $_GET['topic_id'] ?? '';

// Only delete the comment if the current user owns it (or is an admin).
$stmt = db()->prepare('SELECT user_id FROM comments WHERE id = ?');
$stmt->execute([$id]);
$comment = $stmt->fetch();

if ($comment && can_modify((int) $comment['user_id'])) {
    $del = db()->prepare('DELETE FROM comments WHERE id = ?');
    $del->execute([$id]);
}

header('Location: topic.php?id=' . (int) $topicId);
exit;
