<?php
// =========================================================================
// MY PACKAGE / SUBSCRIPTION VIEW
// =========================================================================

$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$_SESSION['user_id']]);
$me = $stmt->fetch();
$rem = ($me['searches_limit'] - $me['searches_used']);
$percent = ($me['searches_limit'] > 0) ? ($me['searches_used'] / $me['searches_limit']) * 100 : 0;
?>
<div class="mb-4"><h3 class="fw-bold">Subscription Details</h3></div>
<div class="row">
    <div class="col-md-6">
        <div class="pkg-card">
            <h5 class="text-muted small text-uppercase fw-bold mb-4">Active Plan</h5>
            <h2 class="fw-bold text-primary mb-1"><?= $me['package_name'] ?? 'Custom Plan' ?></h2>
            <p class="text-muted mb-2">Created: <span class="text-dark fw-bold"><?= format_datetime($me['created_at'], 'M d, Y H:i') ?></span></p>
            <p class="text-muted mb-4">Expires on: <span class="text-dark fw-bold"><?= format_date($me['package_expiry']) ?></span></p>
            <?php if ($me['last_renewal_at']): ?>
                <p class="text-muted mb-4">Last Renewed: <span class="text-dark fw-bold"><?= format_datetime($me['last_renewal_at'], 'M d, Y H:i') ?></span></p>
            <?php endif; ?>
            <div class="progress mb-4" style="height: 10px; border-radius: 10px;">
                <div class="progress-bar bg-primary" style="width: <?= $percent ?>%"></div>
            </div>
            <div class="row g-3">
                <div class="col-6">
                    <div class="p-3 bg-light rounded text-center">
                        <h4 class="mb-0 fw-bold"><?= $rem ?></h4>
                        <span class="text-muted small">Remaining</span>
                    </div>
                </div>
                <div class="col-6">
                    <div class="p-3 bg-light rounded text-center">
                        <h4 class="mb-0 fw-bold"><?= $me['searches_used'] ?></h4>
                        <span class="text-muted small">Consumed</span>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
