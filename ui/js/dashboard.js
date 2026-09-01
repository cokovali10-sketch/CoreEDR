// CoreEDR - Dashboard Page
const Dashboard = (() => {
    let refreshTimer = null;

    async function init() {
        if (refreshTimer) clearInterval(refreshTimer);
        App.onWsMessage(handleWsMessage);
        refreshTimer = setInterval(() => {
            if (App.getCurrentPage() === 'dashboard') render();
        }, 5000);
    }

    function handleWsMessage(msg) {
        if (App.getCurrentPage() !== 'dashboard') return;
        switch (msg.type) {
            case 'scan_complete':
            case 'threat_detected':
            case 'quarantine_update':
                render();
                break;
            case 'activity':
                appendActivity(msg.data);
                break;
        }
    }

    async function render() {
        const content = document.getElementById('page-content');
        try {
            const [stats, alerts, activity] = await Promise.all([
                App.api('GET', '/stats').catch(() => null),
                App.api('GET', '/alerts?limit=10').catch(() => []),
                App.api('GET', '/activity?limit=15').catch(() => []),
            ]);

            const s = stats || { scannerRunning: false, totalScans: 0, threatsDetected: 0, threatsContained: 0 };
            App.updateScannerStatus(s.scannerRunning);

            content.innerHTML = `
                <div class="stats-grid">
                    ${renderStatCard('Scanner Status', s.scannerRunning ? 'Running' : 'Stopped', 'blue', s.scannerRunning ? '&#9679;' : '&#9632;', s.scannerRunning ? 'Actively monitoring' : 'Scanner offline')}
                    ${renderStatCard('Total Scans', formatNumber(s.totalScans), 'green', '&#128269;', 'Lifetime scan count')}
                    ${renderStatCard('Threats Detected', formatNumber(s.threatsDetected), 'red', '&#9888;', 'Malicious items found')}
                    ${renderStatCard('Threats Contained', formatNumber(s.threatsContained), 'orange', '&#128274;', 'Quarantined successfully')}
                </div>

                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 24px;">
                    <div class="section-card">
                        <div class="section-header">
                            <span class="section-title">Recent Alerts</span>
                            <a href="#alerts" class="btn btn-sm btn-outline">View All</a>
                        </div>
                        <div class="section-body no-padding" id="alerts-list">
                            ${renderAlerts(alerts || [])}
                        </div>
                    </div>

                    <div class="section-card">
                        <div class="section-header">
                            <span class="section-title">Live Activity</span>
                        </div>
                        <div class="section-body no-padding">
                            <div class="activity-feed" id="activity-feed">
                                ${renderActivityFeed(activity || [])}
                            </div>
                        </div>
                    </div>
                </div>
            `;
        } catch (err) {
            content.innerHTML = `
                <div class="empty-state">
                    <div class="empty-state-icon">&#9888;</div>
                    <div class="empty-state-text">Failed to load dashboard data</div>
                    <button class="btn btn-primary" style="margin-top: 12px" onclick="Dashboard.render()">Retry</button>
                </div>
            `;
        }
    }

    function renderStatCard(label, value, color, iconHtml, sub) {
        return `
            <div class="stat-card">
                <div class="stat-card-header">
                    <span class="stat-card-label">${escapeHtml(label)}</span>
                    <div class="stat-card-icon ${color}">${iconHtml}</div>
                </div>
                <div class="stat-card-value">${escapeHtml(String(value))}</div>
                <div class="stat-card-sub">${escapeHtml(sub)}</div>
            </div>
        `;
    }

    function renderAlerts(alerts) {
        if (!alerts.length) {
            return '<div class="empty-state"><div class="empty-state-text">No recent alerts</div></div>';
        }
        return alerts.slice(0, 8).map(a => `
            <div class="alert-item" onclick="App.navigate('alerts')">
                <div class="alert-severity ${(a.severity || 'info').toLowerCase()}"></div>
                <div class="alert-content">
                    <div class="alert-title">${escapeHtml(a.title || a.message || 'Alert')}</div>
                    <div class="alert-desc">${escapeHtml(a.source || '')}</div>
                </div>
                <span class="badge badge-${(a.severity || 'info').toLowerCase()}">${escapeHtml(a.severity || 'Info')}</span>
                <span class="alert-time">${TimeUtils.relative(a.timestamp)}</span>
            </div>
        `).join('');
    }

    function renderActivityFeed(items) {
        if (!items.length) {
            return '<div class="empty-state"><div class="empty-state-text">No activity yet</div></div>';
        }
        return items.map(item => {
            const type = item.type || 'info';
            const dotClass = type.includes('scan') ? 'scan' : type.includes('threat') ? 'threat' : type.includes('quarantine') ? 'quarantine' : 'info';
            return `
                <div class="activity-item">
                    <div class="activity-dot ${dotClass}"></div>
                    <div class="activity-text">${escapeHtml(item.message || item.text || '')}</div>
                    <span class="activity-time">${TimeUtils.relative(item.timestamp)}</span>
                </div>
            `;
        }).join('');
    }

    function appendActivity(data) {
        const feed = document.getElementById('activity-feed');
        if (!feed || !data) return;
        const dotClass = (data.type || '').includes('threat') ? 'threat' : 'info';
        const html = `
            <div class="activity-item" style="animation: fade-in 0.3s ease">
                <div class="activity-dot ${dotClass}"></div>
                <div class="activity-text">${escapeHtml(data.message || '')}</div>
                <span class="activity-time">just now</span>
            </div>
        `;
        feed.insertAdjacentHTML('afterbegin', html);
        while (feed.children.length > 20) feed.lastChild.remove();
    }

    function formatNumber(n) {
        if (n === undefined || n === null) return '0';
        if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M';
        if (n >= 1000) return (n / 1000).toFixed(1) + 'K';
        return String(n);
    }

    return { init, render };
})();
