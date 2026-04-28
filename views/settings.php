<?php
// =========================================================================
// SETTINGS / CHANGE PASSWORD VIEW
// =========================================================================
?>
<div class="mb-4"><h3 class="fw-bold">Account Settings</h3></div>
<div class="col-md-5">
    <div class="pkg-card">
        <h5 class="fw-bold mb-4">Change Password</h5>
        <form method="POST">
            <input type="hidden" name="action" value="change_pwd">
            <div class="mb-3">
                <label class="small fw-bold mb-1">Current Password</label>
                <input type="password" name="old_password" class="form-control" required>
            </div>
            <div class="mb-3">
                <label class="small fw-bold mb-1">New Password</label>
                <input type="password" name="new_password" class="form-control" required>
            </div>
            <div class="mb-4">
                <label class="small fw-bold mb-1">Confirm New Password</label>
                <input type="password" name="confirm_password" class="form-control" required>
            </div>
            <button class="btn btn-primary w-100 fw-bold">UPDATE PASSWORD</button>
        </form>
    </div>
</div>
