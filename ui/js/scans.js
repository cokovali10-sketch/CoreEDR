// CoreEDR - Scans Page
const Scans = (() => {
    let scanning = false;

    async function init() {}

    async function render() {
        const content = document.getElementById('page-content');
        try {
            const scans = await App.api('GET', '/scans').catch(() => []);
            content.innerHTML = `
                <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 20px;">
                    <div>
                        <h2 style="font-size: 1.1rem; font-weight: 600;">Scan History</h2>
                        <p style="font-size: 0.85rem; color: var(--text-muted); margin-top: 2px;">View and manage system scans</p>
                    </div>
                    <button class="btn btn-primary" id="start-scan-btn" onclick="Scans.startScan()" ${scanning ? 'disabled' : ''}>
                        ${scanning ? '<span class="spinner" style="width:14px;height:14px;border-width:2px;margin-right:4px"></span> Scanning...' : '&#9654; Start Scan'}
                    </button>
                </div>
                <div id="scan-progress" class="hidden"></div>
                <div class="section-card">
                    <div class="section-body no-padding">
                        <div class="table-container">
                            ${renderScanResults(scans || [])}
                        </div>
                    </div>
                </div>
            `;
        } catch (err) {
            content.innerHTML = `<div class="empty-state"><div class="empty-state-text">Failed to load scan data</div></div>`;
        }
    }

    async function startScan() {
        scanning = true;
        const btn = document.getElementById('start-scan-btn');
        if (btn) {
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner" style="width:14px;height:14px;border-width:2px;margin-right:4px"></span> Scanning...';
        }

        const progress = document.getElementById('scan-progress');
        if (progress) {
            progress.classList.remove('hidden');
            progress.innerHTML = `
                <div class="section-card" style="margin-bottom: 24px">
                    <div class="scan-progress-container">
                        <div class="spinner"></div>
                        <div class="scan-progress-text">Scan in progress...</div>
                        <div class="progress-bar"><div class="progress-fill running" style="width: 0%" id="scan-progress-fill"></div></div>
                    </div>
                </div>
            `;
        }

        try {
            const result = await App.api('POST', '/scans/start');
            Toast.show('Scan completed successfully', 'success');
            simulateProgress(100);
        } catch (err) {
            Toast.show('Failed to start scan: ' + err.message, 'error');
            simulateProgress(0);
        }

        scanning = false;
        setTimeout(() => render(), 500);
    }

    function simulateProgress(target) {
        const fill = document.getElementById('scan-progress-fill');
        if (!fill) return;
        fill.style.width = target + '%';
        if (target === 0) {
            setTimeout(() => {
                const p = document.getElementById('scan-progress');
                if (p) p.classList.add('hidden');
            }, 1000);
        }
    }

    function renderScanResults(scans) {
        if (!scans.length) {
            return '<div class="empty-state"><div class="empty-state-text">No scans performed yet</div></div>';
        }
        return `
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Scan ID</th>
                        <th>Type</th>
                        <th>Status</th>
                        <th>Files Scanned</th>
                        <th>Threats</th>
                        <th>Duration</th>
                        <th>Started</th>
                    </tr>
                </thead>
                <tbody>
                    ${scans.map(s => `
                        <tr class="clickable" onclick="Scans.showDetail('${escapeHtml(s.id || '')}')">
                            <td style="font-family: var(--font-mono); font-size: 0.8rem;">${escapeHtml(truncate(s.id, 8))}</td>
                            <td><span class="badge badge-info">${escapeHtml(s.type || 'Quick')}</span></td>
                            <td><span class="badge ${s.status === 'completed' ? 'badge-success' : s.status === 'running' ? 'badge-info' : 'badge-danger'}">${escapeHtml(s.status || 'unknown')}</span></td>
                            <td>${formatNumber(s.filesScanned || s.files_scanned || 0)}</td>
                            <td><span style="color: ${(s.threats || 0) > 0 ? 'var(--accent-red)' : 'var(--accent-green)'}; font-weight: 600;">${s.threats || 0}</span></td>
                            <td>${s.duration ? s.duration + 's' : 'N/A'}</td>
                            <td style="color: var(--text-muted);">${TimeUtils.relative(s.startTime || s.startedAt)}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        `;
    }

    async function showDetail(scanId) {
        if (!scanId) return;
        try {
            const scan = await App.api('GET', `/scans/${scanId}`);
            if (!scan) {
                Toast.show('Scan details not found', 'error');
                return;
            }
            const bodyHtml = `
                <div class="detail-grid">
                    <span class="detail-label">Scan ID</span>
                    <span class="detail-value mono">${escapeHtml(scan.id)}</span>
                    <span class="detail-label">Type</span>
                    <span class="detail-value">${escapeHtml(scan.type || 'Quick')}</span>
                    <span class="detail-label">Status</span>
                    <span class="detail-value">${escapeHtml(scan.status)}</span>
                    <span class="detail-label">Files Scanned</span>
                    <span class="detail-value">${formatNumber(scan.filesScanned || scan.files_scanned || 0)}</span>
                    <span class="detail-label">Threats Found</span>
                    <span class="detail-value" style="color: ${(scan.threats || 0) > 0 ? 'var(--accent-red)' : 'var(--accent-green)'}">${scan.threats || 0}</span>
                    <span class="detail-label">Duration</span>
                    <span class="detail-value">${scan.duration ? scan.duration + 's' : 'N/A'}</span>
                    <span class="detail-label">Started</span>
                    <span class="detail-value">${TimeUtils.format(scan.startTime || scan.startedAt)}</span>
                    <span class="detail-label">Completed</span>
                    <span class="detail-value">${TimeUtils.format(scan.endTime || scan.completedAt)}</span>
                </div>
                ${scan.threatsList && scan.threatsList.length ? `
                    <h4 style="margin-top: 16px; margin-bottom: 8px; font-size: 0.9rem;">Threats Detected</h4>
                    <table class="data-table">
                        <thead><tr><th>File</th><th>Threat</th><th>Risk</th></tr></thead>
                        <tbody>
                            ${scan.threatsList.map(t => `
                                <tr>
                                    <td style="font-family: var(--font-mono); font-size: 0.8rem;">${escapeHtml(t.file || t.path)}</td>
                                    <td>${escapeHtml(t.name || t.threat || 'Unknown')}</td>
                                    <td><span class="badge badge-${(t.risk || 'medium').toLowerCase()}">${escapeHtml(t.risk || 'Medium')}</span></td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                ` : ''}
            `;
            App.showModal(`Scan Report - ${truncate(scanId, 12)}`, bodyHtml);
        } catch (err) {
            Toast.show('Failed to load scan details', 'error');
        }
    }

    function truncate(str, len) {
        if (!str) return '';
        return str.length > len ? str.substring(0, len) + '...' : str;
    }

    function formatNumber(n) {
        if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M';
        if (n >= 1000) return (n / 1000).toFixed(1) + 'K';
        return String(n);
    }

    return { init, render, startScan, showDetail };
})();
