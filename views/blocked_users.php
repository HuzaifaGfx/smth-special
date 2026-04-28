<?php
// =========================================================================
// BLOCKED USERS VIEW
// =========================================================================

$blocked = get_blocked_users($pdo);
?>
<div class="mb-4"><h3 class="fw-bold">Blocked Users</h3></div>

<?php if (count($blocked) > 0): ?>
<div class="card p-4 border-0 shadow-sm overflow-auto">
    <div class="d-flex justify-content-between align-items-center mb-4">
        <h5 class="fw-bold mb-0">All Blocked Accounts (<?= count($blocked) ?>)</h5>
        <input type="text" id="blockedSearch" class="form-control form-control-sm w-25" placeholder="Search user..." onkeyup="filterBlockedUsers()">
    </div>
    <table class="table align-middle table-danger" id="blockedTable">
        <thead>
            <tr>
                <th>Username</th>
                <th>Role</th>
                <th>Created</th>
                <th>Blocked Date</th>
                <th>Package</th>
                <th>Created By</th>
                <th class="text-center">Actions</th>
            </tr>
        </thead>
        <tbody>
            <?php foreach($blocked as $u): ?>
            <tr>
                <td>
                    <div class="fw-bold b-name"><?= $u['username'] ?></div>
                </td>
                <td><span class="badge bg-light text-dark border"><?= $u['role'] ?></span></td>
                <td><small><?= format_datetime($u['created_at']) ?></small></td>
                <td><small><?= format_date($u['package_expiry']) ?></small></td>
                <td><small><?= $u['package_name'] ?? 'N/A' ?></small></td>
                <td><small><?= $u['created_by'] ?? 'System' ?></small></td>
                <td class="text-center">
                    <?php if(is_super()): ?>
                    <form method="POST" class="d-inline">
                        <input type="hidden" name="action" value="toggle_block">
                        <input type="hidden" name="user_id" value="<?= $u['id'] ?>">
                        <input type="hidden" name="status" value="1">
                        <button type="submit" class="btn btn-sm btn-outline-success">Unblock</button>
                    </form>
                    <form method="POST" class="d-inline" onsubmit="return confirm('Permanently delete this user?');">
                        <input type="hidden" name="action" value="delete_user">
                        <input type="hidden" name="user_id" value="<?= $u['id'] ?>">
                        <button class="btn btn-sm btn-outline-danger">Delete</button>
                    </form>
                    <?php else: ?>
                    <span class="text-muted small">No actions available</span>
                    <?php endif; ?>
                </td>
            </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
</div>
<?php else: ?>
<div class="alert alert-info border-0 shadow-sm">
    <i class="fas fa-info-circle me-2"></i> No blocked users at the moment.
</div>
<?php endif; ?>
