// CoreEDR - Main Application Module
const App = (() => {
    let currentPage = 'dashboard';
    let ws = null;
    let wsReconnectTimer = null;
    let wsReconnectAttempts = 0;
    const WS_MAX_RECONNECT = 10;
    const WS_RECONNECT_DELAY = 2000;
    const dataCache = {};
    const wsListeners = [];

    const API_BASE = '/api';

    const pages = {
        dashboard: { title: 'Dashboard', init: () => Dashboard.init(), render: () => Dashboard.render() },
        scans: { title: 'Scans', init: () => Scans.init(), render: () => Scans.render() },
        quarantine: { title: 'Quarantine', init: () => Quarantine.init(), render: () => Quarantine.render() },
        alerts: { title: 'Alerts', init: () => Alerts.init(), render: () => Alerts.render() },
        settings: { title: 'Settings', init: () => Settings.init(), render: () => Settings.render() },
    };

    async function api(method, path, body = null) {
        const opts = {
            method,
            headers: { 'Content-Type': 'application/json' },
        };
        if (body) opts.body = JSON.stringify(body);
        try {
            const res = await fetch(`${API_BASE}${path}`, opts);
            if (!res.ok) {
                const errText = await res.text().catch(() => res.statusText);
                throw new Error(`HTTP ${res.status}: ${errText}`);
            }
            const text = await res.text();
            return text ? JSON.parse(text) : null;
        } catch (err) {
            if (err.message.includes('Failed to fetch')) {
                Toast.show('Cannot connect to CoreEDR service', 'error');
            }
            throw err;
        }
    }

    function connectWebSocket() {
        if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) return;

        const proto = location.protocol === 'https:' ? 'wss' : 'ws';
        const url = `${proto}://${location.host}/ws`;
        updateConnectionStatus('connecting');

        try {
            ws = new WebSocket(url);
        } catch (e) {
            updateConnectionStatus('disconnected');
            scheduleReconnect();
            return;
        }

        ws.onopen = () => {
            wsReconnectAttempts = 0;
            updateConnectionStatus('connected');
            Toast.show('Real-time connection established', 'success');
        };

        ws.onmessage = (event) => {
            try {
                const msg = JSON.parse(event.data);
                wsListeners.forEach(fn => fn(msg));
            } catch (e) { /* ignore malformed messages */ }
        };

        ws.onclose = () => {
            updateConnectionStatus('disconnected');
            scheduleReconnect();
        };

        ws.onerror = () => {
            ws.close();
        };
    }

    function scheduleReconnect() {
        if (wsReconnectTimer) clearTimeout(wsReconnectTimer);
        if (wsReconnectAttempts >= WS_MAX_RECONNECT) return;
        wsReconnectTimer = setTimeout(() => {
            wsReconnectAttempts++;
            connectWebSocket();
        }, WS_RECONNECT_DELAY * Math.min(wsReconnectAttempts + 1, 5));
    }

    function updateConnectionStatus(status) {
        const dot = document.getElementById('ws-dot');
        const text = document.getElementById('ws-text');
        if (!dot || !text) return;
        dot.className = `status-dot status-${status}`;
        const labels = { connected: 'Connected', disconnected: 'Disconnected', connecting: 'Connecting...' };
        text.textContent = labels[status] || status;
    }

    function updateScannerStatus(running) {
        const dot = document.getElementById('status-dot');
        const text = document.getElementById('status-text');
        if (!dot || !text) return;
        dot.className = `status-dot status-${running ? 'running' : 'stopped'}`;
        text.textContent = running ? 'Scanner Running' : 'Scanner Stopped';
    }

    function onWsMessage(fn) {
        wsListeners.push(fn);
    }

    function navigate(page) {
        if (!pages[page]) page = 'dashboard';
        currentPage = page;

        document.querySelectorAll('.nav-link').forEach(link => {
            link.classList.toggle('active', link.dataset.page === page);
        });

        const title = pages[page].title;
        document.getElementById('page-title').textContent = title;
        document.title = `CoreEDR - ${title}`;

        const content = document.getElementById('page-content');
        content.innerHTML = '<div class="loading-spinner"><div class="spinner"></div></div>';

        pages[page].init().then(() => pages[page].render());

        history.replaceState(null, '', `#${page}`);

        closeMobileSidebar();
    }

    function getCached(key) {
        return dataCache[key];
    }

    function setCached(key, value) {
        dataCache[key] = value;
    }

    function openMobileSidebar() {
        const sidebar = document.getElementById('sidebar');
        sidebar.classList.add('open');
        let overlay = document.querySelector('.sidebar-overlay');
        if (!overlay) {
            overlay = document.createElement('div');
            overlay.className = 'sidebar-overlay';
            overlay.addEventListener('click', closeMobileSidebar);
            document.getElementById('app').appendChild(overlay);
        }
        overlay.classList.add('active');
    }

    function closeMobileSidebar() {
        document.getElementById('sidebar').classList.remove('open');
        const overlay = document.querySelector('.sidebar-overlay');
        if (overlay) overlay.classList.remove('active');
    }

    function showModal(title, bodyHtml, footerHtml = '') {
        document.getElementById('modal-title').textContent = title;
        document.getElementById('modal-body').innerHTML = bodyHtml;
        document.getElementById('modal-footer').innerHTML = footerHtml;
        document.getElementById('modal-overlay').classList.remove('hidden');
    }

    function closeModal() {
        document.getElementById('modal-overlay').classList.add('hidden');
    }

    function updateTimestamp() {
        const el = document.getElementById('last-updated');
        if (el) el.textContent = `Updated: ${new Date().toLocaleTimeString()}`;
    }

    function init() {
        const hash = location.hash.replace('#', '') || 'dashboard';
        navigate(hash);

        document.querySelectorAll('.nav-link').forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                navigate(link.dataset.page);
            });
        });

        document.getElementById('mobile-menu-btn').addEventListener('click', openMobileSidebar);
        document.getElementById('modal-close').addEventListener('click', closeModal);
        document.getElementById('modal-overlay').addEventListener('click', (e) => {
            if (e.target === e.currentTarget) closeModal();
        });

        window.addEventListener('hashchange', () => {
            const page = location.hash.replace('#', '') || 'dashboard';
            if (page !== currentPage) navigate(page);
        });

        connectWebSocket();
        updateTimestamp();
        setInterval(updateTimestamp, 30000);
    }

    return {
        init,
        navigate,
        api,
        onWsMessage,
        getCached,
        setCached,
        showModal,
        closeModal,
        updateScannerStatus,
        getCurrentPage: () => currentPage,
    };
})();

// Toast Notification System
const Toast = (() => {
    function show(message, type = 'info', duration = 4000) {
        const container = document.getElementById('toast-container');
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;

        const icons = {
            success: '&#10003;',
            error: '&#10007;',
            warning: '&#9888;',
            info: '&#8505;'
        };

        toast.innerHTML = `
            <span class="toast-icon">${icons[type] || icons.info}</span>
            <span>${message}</span>
        `;

        container.appendChild(toast);

        setTimeout(() => {
            toast.classList.add('removing');
            setTimeout(() => toast.remove(), 300);
        }, duration);
    }

    return { show };
})();

// Time formatting helpers
const TimeUtils = {
    relative(ts) {
        if (!ts) return 'N/A';
        const now = Date.now();
        const diff = now - new Date(ts).getTime();
        if (diff < 0) return 'just now';
        const secs = Math.floor(diff / 1000);
        if (secs < 60) return `${secs}s ago`;
        const mins = Math.floor(secs / 60);
        if (mins < 60) return `${mins}m ago`;
        const hrs = Math.floor(mins / 60);
        if (hrs < 24) return `${hrs}h ago`;
        const days = Math.floor(hrs / 24);
        return `${days}d ago`;
    },
    format(ts) {
        if (!ts) return 'N/A';
        return new Date(ts).toLocaleString();
    }
};

// Escape HTML to prevent XSS
function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = String(str);
    return div.innerHTML;
}
