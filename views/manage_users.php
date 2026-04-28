<?php
// =========================================================================
// MANAGE USERS VIEW
// =========================================================================

$total_users = get_user_count($pdo);
$all_users = get_all_users($pdo);
?>
<div class="mb-4 d-flex justify-content-between align-items-center">
    <h3 class="fw-bold">Manage Accounts</h3>
    <div class="stat-card" style="width: 200px;">
        <div class="stat-number"><?= $total_users ?></div>
        <div class="stat-label">Total Users</div>
    </div>
</div>

<div class="card p-4 mb-4 border-0 shadow-sm">
    <h5 class="fw-bold mb-3">Create New Account</h5>
    <form method="POST" class="row g-2">
        <input type="hidden" name="action" value="create_user">
        <div class="col-md-3"><input type="text" name="new_username" class="form-control" placeholder="Username" required></div>
        <div class="col-md-3">
            <select name="new_role" class="form-select">
                <option value="user">User</option>
                <?php if(is_super()): ?>
                    <option value="admin">Admin</option>
                    <option value="superadmin">Super Admin</option>
                <?php endif; ?>
            </select>
        </div>
        <div class="col-md-3">
            <select name="package_name" class="form-select">
                <?php foreach(PACKAGES as $name => $v): ?><option value="<?= $name ?>"><?= $name ?></option><?php endforeach; ?>
            </select>
        </div>
        <div class="col-md-3"><button class="btn btn-primary w-100 fw-bold">CREATE</button></div>
    </form>
</div>

<div class="card p-4 border-0 shadow-sm overflow-auto">
    <div class="d-flex justify-content-between align-items-center mb-4">
        <h5 class="fw-bold mb-0">All Accounts</h5>
        <input type="text" id="userSearch" class="form-control form-control-sm w-25" placeholder="Search user..." onkeyup="filterUsers()">
    </div>
    <table class="table align-middle" id="userTable">
        <thead>
            <tr>
                <th>Username</th>
                <th>Role</th>
                <th>Created</th>
                <th>Expiry</th>
                <th>Last Renewed</th>
                <th>Credits</th>
                <th>Status</th>
                <th>PDF</th>
                <th class="text-center">Actions</th>
            </tr>
        </thead>
        <tbody>
            <?php foreach($all_users as $u): ?>
            <tr class="<?= $u['is_active'] ? '' : 'table-danger' ?>">
                <td>
                    <div class="fw-bold u-name"><?= $u['username'] ?></div>
                    <div class="text-muted" style="font-size: 10px;">Created by: <?= $u['created_by'] ?? 'System' ?></div>
                </td>
                <td><span class="badge bg-light text-dark border"><?= $u['role'] ?></span></td>
                <td><small><?= format_date($u['created_at']) ?></small></td>
                <td><small><?= format_date($u['package_expiry']) ?></small></td>
                <td>
                    <?php if($u['last_renewal_at']): ?>
                        <small><?= format_date($u['last_renewal_at']) ?></small>
                    <?php else: ?>
                        <small class="text-muted">Never</small>
                    <?php endif; ?>
                </td>
                <td><?= $u['role']=='user' ? ($u['searches_limit'] - $u['searches_used']) : '∞' ?></td>
                <td>
                    <?php if(is_super()): ?>
                    <form method="POST" class="d-inline">
                        <input type="hidden" name="action" value="toggle_block">
                        <input type="hidden" name="user_id" value="<?= $u['id'] ?>">
                        <input type="hidden" name="status" value="<?= $u['is_active'] ? 0 : 1 ?>">
                        <button type="submit" class="btn btn-sm <?= $u['is_active'] ? 'btn-outline-success' : 'btn-danger' ?>">
                            <?= $u['is_active'] ? 'Active' : 'Blocked' ?>
                        </button>
                    </form>
                    <?php else: ?>
                        <span class="badge bg-<?= $u['is_active'] ? 'success' : 'danger' ?>"><?= $u['is_active'] ? 'Active' : 'Blocked' ?></span>
                    <?php endif; ?>
                </td>
                <td>
                    <?php if(is_super()): ?>
                    <form method="POST" class="d-inline">
                        <input type="hidden" name="action" value="toggle_pdf">
                        <input type="hidden" name="user_id" value="<?= $u['id'] ?>">
                        <input type="hidden" name="pdf_status" value="<?= $u['can_export_pdf'] ? 0 : 1 ?>">
                        <button type="submit" class="btn btn-sm <?= $u['can_export_pdf'] ? 'btn-success' : 'btn-secondary' ?>">
                            <?= $u['can_export_pdf'] ? 'Yes' : 'No' ?>
                        </button>
                    </form>
                    <?php else: ?>
                        <span class="badge bg-light text-dark"><?= $u['can_export_pdf'] ? 'Yes' : 'No' ?></span>
                    <?php endif; ?>
                </td>
                <td class="text-center">
                    <form method="POST" class="d-inline">
                        <input type="hidden" name="action" value="reset_device">
                        <input type="hidden" name="user_id" value="<?= $u['id'] ?>">
                        <button class="btn btn-sm btn-outline-warning" title="Reset Device"><i class="fas fa-mobile-alt"></i></button>
                    </form>
                    <button class="btn btn-sm btn-outline-success" data-bs-toggle="modal" data-bs-target="#renewModal<?= $u['id'] ?>" title="Renew"><i class="fas fa-sync-alt"></i></button>
                    
                    <?php if(is_super()): ?>
                        <button class="btn btn-sm btn-outline-primary" data-bs-toggle="modal" data-bs-target="#editModal<?= $u['id'] ?>" title="Edit Username"><i class="fas fa-edit"></i></button>
                        <form method="POST" class="d-inline" onsubmit="return confirm('Permanently delete this user?');">
                            <input type="hidden" name="action" value="delete_user">
                            <input type="hidden" name="user_id" value="<?= $u['id'] ?>">
                            <button class="btn btn-sm btn-outline-danger" title="Delete"><i class="fas fa-trash"></i></button>
                        </form>
                    <?php endif; ?>
                </td>
            </tr>

            <!-- Edit Username Modal -->
            <div class="modal fade" id="editModal<?= $u['id'] ?>" tabindex="-1">
                <div class="modal-dialog modal-sm modal-dialog-centered">
                    <div class="modal-content border-0 shadow">
                        <div class="modal-header"><h6 class="modal-title fw-bold">Edit Username</h6><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
                        <form method="POST">
                            <div class="modal-body">
                                <input type="hidden" name="action" value="change_username">
                                <input type="hidden" name="user_id" value="<?= $u['id'] ?>">
                                <input type="text" name="new_username" class="form-control" value="<?= $u['username'] ?>" required>
                            </div>
                            <div class="modal-footer border-0"><button type="submit" class="btn btn-primary w-100 fw-bold">SAVE CHANGES</button></div>
                        </form>
                    </div>
                </div>
            </div>

            <!-- Renew Account Modal -->
            <div class="modal fade" id="renewModal<?= $u['id'] ?>" tabindex="-1">
                <div class="modal-dialog modal-sm modal-dialog-centered">
                    <div class="modal-content border-0 shadow">
                        <div class="modal-header"><h6 class="modal-title fw-bold">Renew Account</h6><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
                        <form method="POST">
                            <div class="modal-body">
                                <input type="hidden" name="action" value="renew_user">
                                <input type="hidden" name="user_id" value="<?= $u['id'] ?>">
                                <select name="package_name" class="form-select">
                                    <?php foreach(PACKAGES as $pn => $pv): ?><option value="<?= $pn ?>"><?= $pn ?></option><?php endforeach; ?>
                                </select>
                            </div>
                            <div class="modal-footer border-0"><button type="submit" class="btn btn-primary w-100 fw-bold">RENEW NOW</button></div>
                        </form>
                    </div>
                </div>
            </div>
            <?php endforeach; ?>
        </tbody>
    </table>
</div>
