// =========================================================================
// TRACE VERISYS - JAVASCRIPT
// =========================================================================

const USER_CAN_PDF = (function() {
    // Set by PHP in layout.php
    return window.USER_CAN_PDF !== undefined ? window.USER_CAN_PDF : 0;
})();

/**
 * Export results to PDF
 */
function exportPDF() {
    const query = document.getElementById('query').value.trim() || 'Results';
    const element = document.getElementById('results');
    const opt = {
        margin: [0.3, 0.3],
        filename: 'Report_' + query + '.pdf',
        image: { type: 'jpeg', quality: 0.98 },
        html2canvas: { scale: 2, useCORS: true },
        jsPDF: { unit: 'in', format: 'a4', orientation: 'portrait' }
    };
    html2pdf().set(opt).from(element).save();
}

/**
 * Filter users in manage users table
 */
function filterUsers() {
    let input = document.getElementById("userSearch").value.toUpperCase();
    let tr = document.getElementById("userTable").getElementsByTagName("tr");
    for (let i = 1; i < tr.length; i++) {
        let td = tr[i].getElementsByClassName("u-name")[0];
        if (td) {
            tr[i].style.display = (td.textContent || td.innerText).toUpperCase().indexOf(input) > -1 ? "" : "none";
        }
    }
}

/**
 * Filter blocked users in blocked users table
 */
function filterBlockedUsers() {
    let input = document.getElementById("blockedSearch").value.toUpperCase();
    let tr = document.getElementById("blockedTable").getElementsByTagName("tr");
    for (let i = 1; i < tr.length; i++) {
        let td = tr[i].getElementsByClassName("b-name")[0];
        if (td) {
            tr[i].style.display = (td.textContent || td.innerText).toUpperCase().indexOf(input) > -1 ? "" : "none";
        }
    }
}

/**
 * Render content recursively (handles objects, arrays, images)
 */
function renderContent(data) {
    if (!data) return "--";

    if (typeof data === 'object' && !Array.isArray(data)) {
        let subRows = '';
        for (const [key, val] of Object.entries(data)) {
            subRows += `<tr><td class="result-label" style="font-size:10px;">${key.replace(/_/g, ' ')}</td><td>${renderContent(val)}</td></tr>`;
        }
        return `<div class="nested-table-container"><table class="result-table">${subRows}</table></div>`;
    }

    // Check if it's base64 encoded image
    if (typeof data === 'string' && data.startsWith('data:image')) {
        return `<img src="${data}" class="img-detect" onclick="window.open(this.src)">`;
    }

    return data;
}

/**
 * Perform search and display results
 */
async function doSearch() {
    const q = document.getElementById('query').value.trim();
    const resDiv = document.getElementById('results');
    const pdfBtn = document.getElementById('download-pdf');

    if (!q) return;

    pdfBtn.style.display = 'none';
    resDiv.innerHTML = '<div class="col-12 text-center p-5"><div class="spinner-border text-primary"></div></div>';

    try {
        const response = await fetch('?page=dashboard', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: 'query=' + encodeURIComponent(q)
        });

        const data = await response.json();

        if (data.error) {
            resDiv.innerHTML = `<div class="col-12"><div class="alert alert-danger">${data.error}</div></div>`;
            return;
        }

        resDiv.innerHTML = '';
        let recordCounter = 1;
        let hasResults = false;

        for (const [apiName, body] of Object.entries(data)) {
            // Handle different response structures
            let items = Array.isArray(body) ? body : (typeof body === 'object' ? Object.values(body).find(v => Array.isArray(v)) || [body] : [body]);

            items.forEach((item) => {
                if (typeof item !== 'object' || item === null) return;

                hasResults = true;
                const col = document.createElement('div');
                col.className = 'col-lg-4 col-md-6 col-sm-12';

                let innerRows = '';
                for (const [k, v] of Object.entries(item)) {
                    innerRows += `<tr><td class="result-label">${k.replace(/_/g, ' ')}</td><td class="fw-bold">${renderContent(v)}</td></tr>`;
                }

                col.innerHTML = `<div class="result-card shadow-sm">
                    <div class="result-header d-flex justify-content-between">
                        <span>${apiName}</span>
                        <span class="badge bg-primary">RECORD ${recordCounter}</span>
                    </div>
                    <table class="result-table">${innerRows}</table>
                </div>`;

                resDiv.appendChild(col);
                recordCounter++;
            });
        }

        if (hasResults && USER_CAN_PDF) {
            pdfBtn.style.display = 'block';
        }

    } catch (e) {
        resDiv.innerHTML = '<div class="alert alert-danger">Error fetching data.</div>';
    }
}

// Allow Enter key to trigger search
document.addEventListener('DOMContentLoaded', function() {
    const queryInput = document.getElementById('query');
    if (queryInput) {
        queryInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                doSearch();
            }
        });
    }
});
