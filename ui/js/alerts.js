// CoreEDR - Alerts Page
const Alerts = (() => {
    let allAlerts = [];
    let activeFilter = 'all';

    async function init() {
        App.onWsMessage(handleWsMessage);
    }

    function handleWsMessage(msg) {
        if (App.getCurrentPage() !== 'alerts') return;
        if (msg.type === 'alert' || msg.type === 'threat_detected') {
            render();
        }
    }

    async function render() {
        const content = document.getElementById('page-content');
        try {
            const alerts = await App.api('GET', '/alerts').catch(() => []);
            allAlerts = alerts || [];
            const counts = getCounts();
            content.innerHTML = `
                <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 20px; flex-wrap: wrap; gap: 12px;">
                    <div>
                        <h2 style="font-size: 1.1rem; font-weight: 600;">Security Alerts</h2>
                        <p style="font-size: 0.85rem; color: var(--text-muted); margin-top: 2px;">Monitor and manage security events</p>
                    </div>
                </div>
                <div class="section-card">
                    <div class="filters-bar">
                        <button class="filter-btn ${activeFilter === 'all' ? 'active' : ''}" onclick="Alerts.filterBySeverity('all')">All (${counts.all})</button>
                        <button class="filter-btn ${activeFilter === 'critical' ? 'active' : ''}" onclick="Alerts.filterBySeverity('critical')" style="color: var(--severity-critical);">Critical (${counts.critical})</button>
                        <button class="filter-btn ${activeFilter === 'high' ? 'active' : ''}" onclick="Alerts.filterBySeverity('high')" style="color: var(--severity-high);">High (${counts.high})</button>
                        <button class="filter-btn ${activeFilter === 'medium' ? 'active' : ''}" onclick="Alerts.filterBySeverity('medium')" style="color: var(--severity-medium);">Medium (${counts.medium})</button>
                        <button class="filter-btn ${activeFilter === 'low' ? 'active' : ''}" onclick="Alerts.filterBySeverity('low')" style="color: var(--severity-low);">Low (${counts.low})</button>
                        <button class="filter-btn ${activeFilter === 'info' ? 'active' : ''}" onclick="Alerts.filterBySeverity('info')" style="color: var(--severity-info);">Info (${counts.info})</button>
                    </div>
                    <div id="alerts-table-container" class="section-body no-padding">
                        ${renderAlertList(allAlerts)}
                    </div>
                </div>
            `;
        } catch (err) {
            content.innerHTML = `<div class="empty-state"><div class="empty-state-text">Failed to load alerts</div></div>`;
        }
    }

    function getCounts() {
        const counts = { all: allAlerts.length, critical: 0, high: 0, medium: 0, low: 0, info: 0 };
        allAlerts.forEach(a => {
            const s = (a.severity || 'info').toLowerCase();
            if (counts[s] !== undefined) counts[s]++;
        });
        return counts;
    }

    function renderAlertList(alerts) {
        let filtered = alerts;
        if (activeFilter !== 'all') {
            filtered = alerts.filter(a => (a.severity || 'info').toLowerCase() === activeFilter);
        }

        if (!filtered.length) {
            return '<div class="empty-state"><div class="empty-state-text">No alerts match the current filter</div></div>';
        }

        return `
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Alert</th>
                        <th>Source</th>
                        <th>Time</th>
                        <th>Status</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    ${filtered.map(a => `
                        <tr>
                            <td><span class="badge badge-${(a.severity || 'info').toLowerCase()}">${escapeHtml(a.severity || 'Info')}</span></td>
                            <td style="font-weight: 500; max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; cursor: pointer;" onclick="Alerts.showDetail('${escapeHtml(a.id || '')}')" title="${escapeHtml(a.message || a.title || '')}">${escapeHtml(a.title || a.message || 'Alert')}</td>
                            <td style="color: var(--text-muted);">${escapeHtml(a.source || 'System')}</td>
                            <td style="white-space: nowrap; color: var(--text-muted);">${TimeUtils.relative(a.timestamp)}</td>
                            <td><span class="badge ${a.acknowledged ? 'badge-success' : 'badge-info'}">${a.acknowledged ? 'Acknowledged' : 'Active'}</span></td>
                            <td>
                                <div style="display: flex; gap: 4px;">
                                    ${!a.acknowledged ? `<button class="btn btn-sm btn-outline" onclick="Alerts.acknowledgeAlert('${escapeHtml(a.id)}')">Acknowledge</button>` : ''}
                                    <button class="btn btn-sm btn-outline" onclick="Alerts.showDetail('${escapeHtml(a.id || '')}')">Details</button>
                                </div>
                            </td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        `;
    }

    function filterBySeverity(severity) {
        activeFilter = severity;
        const container = document.getElementById('alerts-table-container');
        if (container) container.innerHTML = renderAlertList(allAlerts);

        document.querySelectorAll('.filter-btn').forEach(btn => {
            const btnSeverity = btn.textContent.split('(')[0].trim().toLowerCase();
            btn.classList.toggle('active', (severity === 'all' && btnSeverity === 'all') || btnSeverity === severity);
        });
    }

    async function acknowledgeAlert(id) {
        if (!id) return;
        try {
            await App.api('POST', `/alerts/${id}/acknowledge`);
            Toast.show('Alert acknowledged', 'success');
            render();
            updateBadge();
        } catch (err) {
            Toast.show('Failed to acknowledge alert: ' + err.message, 'error');
        }
    }

    async function showDetail(id) {
        if (!id) return;
        try {
            const alert = await App.api('GET', `/alerts/${id}`);
            if (!alert) {
                Toast.show('Alert not found', 'error');
                return;
            }
            const bodyHtml = `
                <div class="detail-grid">
                    <span class="detail-label">Alert ID</span>
                    <span class="detail-value mono">${escapeHtml(alert.id)}</span>
                    <span class="detail-label">Severity</span>
                    <span class="detail-value"><span class="badge badge-${(alert.severity || 'info').toLowerCase()}">${escapeHtml(alert.severity || 'Info')}</span></span>
                    <span class="detail-label">Title</span>
                    <span class="detail-value">${escapeHtml(alert.title || alert.message || 'N/A')}</span>
                    <span class="detail-label">Source</span>
                    <span class="detail-value">${escapeHtml(alert.source || 'System')}</span>
                    <span class="detail-label">Description</span>
                    <span class="detail-value">${escapeHtml(alert.description || alert.message || 'No additional details')}</span>
                    <span class="detail-label">Timestamp</span>
                    <span class="detail-value">${TimeUtils.format(alert.timestamp)}</span>
                    <span class="detail-label">Status</span>
                    <span class="detail-value">${alert.acknowledged ? 'Acknowledged' : 'Active'}</span>
                    ${alert.processName ? `
                        <span class="detail-label">Process</span>
                        <span class="detail-value mono">${escapeHtml(alert.processName)}</span>
                    ` : ''}
                    ${alert.filePath ? `
                        <span class="detail-label">File Path</span>
                        <span class="detail-value mono" style="word-break: break-all;">${escapeHtml(alert.filePath)}</span>
                    ` : ''}
                </div>
            `;
            const footerHtml = !alert.acknowledged
                ? `<button class="btn btn-primary" onclick="Alerts.acknowledgeAlert('${escapeHtml(alert.id)}'); App.closeModal();">Acknowledge</button>`
                : '';
            App.showModal('Alert Details', bodyHtml, footerHtml);
        } catch (err) {
            Toast.show('Failed to load alert details', 'error');
        }
    }

    async function updateBadge() {
        try {
            const alerts = await App.api('GET', '/alerts');
            const count = (alerts || []).filter(a => !a.acknowledged).length;
            const badge = document.getElementById('alert-badge');
            if (badge) {
                badge.textContent = count;
                badge.classList.toggle('hidden', count === 0);
            }
        } catch (e) { /* ignore */ }
    }

    return { init, render, filterBySeverity, acknowledgeAlert, showDetail, updateBadge };
})();
