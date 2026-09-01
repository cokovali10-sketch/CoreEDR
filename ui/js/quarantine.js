// CoreEDR - Quarantine Page
const Quarantine = (() => {
    let allEntries = [];

    async function init() {}

    async function render() {
        const content = document.getElementById('page-content');
        try {
            const entries = await App.api('GET', '/quarantine').catch(() => []);
            allEntries = entries || [];
            content.innerHTML = `
                <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 20px; flex-wrap: wrap; gap: 12px;">
                    <div>
                        <h2 style="font-size: 1.1rem; font-weight: 600;">Quarantined Items</h2>
                        <p style="font-size: 0.85rem; color: var(--text-muted); margin-top: 2px;">Isolated threats and suspicious processes</p>
                    </div>
                    <div class="search-box" style="max-width: 280px;">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
                        </svg>
                        <input type="text" placeholder="Search quarantine..." id="quarantine-search" oninput="Quarantine.filterEntries(this.value)">
                    </div>
                </div>
                <div class="section-card">
                    <div class="section-body no-padding">
                        <div class="table-container" id="quarantine-table">
                            ${renderTable(allEntries)}
                        </div>
                    </div>
                </div>
            `;
        } catch (err) {
            content.innerHTML = `<div class="empty-state"><div class="empty-state-text">Failed to load quarantine data</div></div>`;
        }
    }

    function renderTable(entries) {
        if (!entries.length) {
            return '<div class="empty-state"><div class="empty-state-text">No quarantined items</div></div>';
        }
        return `
            <table class="data-table">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Process</th>
                        <th>PID</th>
                        <th>Risk Score</th>
                        <th>Reason</th>
                        <th>Time</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    ${entries.map(e => `
                        <tr>
                            <td style="font-family: var(--font-mono); font-size: 0.8rem;">${escapeHtml(truncateId(e.id))}</td>
                            <td style="font-weight: 500;">${escapeHtml(e.process || e.name || 'Unknown')}</td>
                            <td style="font-family: var(--font-mono);">${escapeHtml(String(e.pid || 'N/A'))}</td>
                            <td>${renderRiskScore(e.riskScore || e.risk_score || 0)}</td>
                            <td style="max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(e.reason || '')}">${escapeHtml(e.reason || 'Suspicious activity')}</td>
                            <td style="color: var(--text-muted); white-space: nowrap;">${TimeUtils.relative(e.timestamp || e.quarantinedAt)}</td>
                            <td>
                                <div style="display: flex; gap: 4px;">
                                    <button class="btn btn-sm btn-success" onclick="Quarantine.restoreEntry('${escapeHtml(e.id)}')" title="Restore">&#8630; Restore</button>
                                    <button class="btn btn-sm btn-danger" onclick="Quarantine.deleteEntry('${escapeHtml(e.id)}')" title="Delete">&#10005; Delete</button>
                                </div>
                            </td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        `;
    }

    function renderRiskScore(score) {
        let color = 'var(--accent-green)';
        let cls = 'badge-success';
        if (score >= 80) { color = 'var(--severity-critical)'; cls = 'badge-critical'; }
        else if (score >= 60) { color = 'var(--severity-high)'; cls = 'badge-high'; }
        else if (score >= 40) { color = 'var(--severity-medium)'; cls = 'badge-medium'; }
        else if (score >= 20) { color = 'var(--severity-low)'; cls = 'badge-low'; }
        return `<span class="badge ${cls}">${score}</span>`;
    }

    function filterEntries(query) {
        const q = query.toLowerCase().trim();
        if (!q) {
            const container = document.getElementById('quarantine-table');
            if (container) container.innerHTML = renderTable(allEntries);
            return;
        }
        const filtered = allEntries.filter(e =>
            (e.process || e.name || '').toLowerCase().includes(q) ||
            (e.reason || '').toLowerCase().includes(q) ||
            String(e.pid || '').includes(q) ||
            (e.id || '').toLowerCase().includes(q)
        );
        const container = document.getElementById('quarantine-table');
        if (container) container.innerHTML = renderTable(filtered);
    }

    async function restoreEntry(id) {
        if (!confirm('Are you sure you want to restore this item?')) return;
        try {
            await App.api('POST', `/quarantine/${id}/restore`);
            Toast.show('Item restored successfully', 'success');
            render();
        } catch (err) {
            Toast.show('Failed to restore item: ' + err.message, 'error');
        }
    }

    async function deleteEntry(id) {
        if (!confirm('Are you sure you want to permanently delete this item?')) return;
        try {
            await App.api('DELETE', `/quarantine/${id}`);
            Toast.show('Item deleted permanently', 'success');
            render();
        } catch (err) {
            Toast.show('Failed to delete item: ' + err.message, 'error');
        }
    }

    function truncateId(id) {
        if (!id) return 'N/A';
        return id.length > 8 ? id.substring(0, 8) + '..' : id;
    }

    return { init, render, filterEntries, restoreEntry, deleteEntry };
})();
