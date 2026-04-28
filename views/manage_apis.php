<?php
// =========================================================================
// MANAGE APIS VIEW (SUPER ADMIN ONLY)
// =========================================================================

$all_apis = $pdo->query("SELECT * FROM apis")->fetchAll();
?>
<div class="card p-4 mb-4 border-0 shadow-sm">
    <h5 class="fw-bold mb-3">Add API Source</h5>
    <form method="POST" class="row g-2">
        <input type="hidden" name="action" value="add_api">
        <div class="col-md-4"><input type="text" name="api_name" class="form-control" placeholder="API Name" required></div>
        <div class="col-md-6"><input type="text" name="api_url" class="form-control" placeholder="URL with [QUERY]" required></div>
        <div class="col-md-2"><button class="btn btn-primary w-100 fw-bold">ADD</button></div>
    </form>
</div>
<div class="card p-4 border-0 shadow-sm overflow-auto">
    <h5 class="fw-bold mb-4">Active API Endpoints</h5>
    <table class="table">
        <thead>
            <tr>
                <th>Name</th>
                <th>URL</th>
                <th>Action</th>
            </tr>
        </thead>
        <tbody>
            <?php foreach($all_apis as $api): ?>
            <tr>
                <td class="fw-bold"><?= $api['api_name'] ?></td>
                <td class="small text-muted"><?= $api['api_url_template'] ?></td>
                <td>
                    <form method="POST" class="d-inline">
                        <input type="hidden" name="action" value="delete_api">
                        <input type="hidden" name="api_id" value="<?= $api['id'] ?>">
                        <button class="btn btn-sm btn-danger">Delete</button>
                    </form>
                </td>
            </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
</div>
