<?php
// =========================================================================
// DASHBOARD VIEW
// =========================================================================
?>
<div class="mb-4 d-flex justify-content-between align-items-center">
    <h3 class="fw-bold">Database Scan</h3>
    <button id="download-pdf" class="btn btn-danger btn-sm fw-bold" style="display:none;" onclick="exportPDF()">
        <i class="fas fa-file-pdf me-2"></i> PDF
    </button>
</div>
<div class="input-group input-group-lg shadow-sm mb-5">
    <input type="text" id="query" class="form-control border-0 px-4" placeholder="Enter your Query...">
    <button class="btn btn-primary px-4 fw-bold" onclick="doSearch()" id="btn-s">SCAN</button>
</div>
<div id="results" class="row g-4"></div>
