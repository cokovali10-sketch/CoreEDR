// CoreEDR - Settings Page
const Settings = (() => {
    let config = null;

    async function init() {}

    async function render() {
        const content = document.getElementById('page-content');
        try {
            config = await App.api('GET', '/config').catch(() => ({}));
            content.innerHTML = `
                <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 20px;">
                    <div>
                        <h2 style="font-size: 1.1rem; font-weight: 600;">Settings</h2>
                        <p style="font-size: 0.85rem; color: var(--text-muted); margin-top: 2px;">Configure CoreEDR behavior and detection rules</p>
                    </div>
                    <div style="display: flex; gap: 8px;">
                        <button class="btn btn-outline" onclick="Settings.reloadConfig()">&#8635; Reload</button>
                        <button class="btn btn-primary" onclick="Settings.saveConfig()">&#10003; Save Config</button>
                    </div>
                </div>

                <div class="section-card" style="margin-bottom: 24px;">
                    <div class="section-header">
                        <span class="section-title">Configuration</span>
                        <span style="font-size: 0.8rem; color: var(--text-muted);">JSON format</span>
                    </div>
                    <div class="section-body">
                        <div class="form-group">
                            <label class="form-label">Configuration File</label>
                            <textarea id="config-editor" class="form-textarea" spellcheck="false" style="min-height: 320px;">${escapeHtml(JSON.stringify(config || {}, null, 2))}</textarea>
                        </div>
                        <div id="config-error" style="color: var(--accent-red); font-size: 0.85rem; display: none;"></div>
                    </div>
                </div>

                <div class="section-card">
                    <div class="section-header">
                        <span class="section-title">Detection Rules</span>
                        <button class="btn btn-sm btn-primary" onclick="Settings.addRule()">+ Add Rule</button>
                    </div>
                    <div class="section-body no-padding">
                        <div class="table-container" id="rules-table">
                            ${renderRulesTable()}
                        </div>
                    </div>
                </div>
            `;
        } catch (err) {
            content.innerHTML = `<div class="empty-state"><div class="empty-state-text">Failed to load settings</div></div>`;
        }
    }

    function renderRulesTable() {
        const rules = config?.rules || config?.detectionRules || [];
        if (!rules.length) {
            return '<div class="empty-state"><div class="empty-state-text">No rules defined. Add a rule or edit the configuration directly.</div></div>';
        }
        return `
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Rule Name</th>
                        <th>Severity</th>
                        <th>Enabled</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    ${rules.map((r, i) => `
                        <tr>
                            <td style="font-weight: 500;">${escapeHtml(r.name || r.id || `Rule ${i + 1}`)}</td>
                            <td><span class="badge badge-${(r.severity || 'medium').toLowerCase()}">${escapeHtml(r.severity || 'Medium')}</span></td>
                            <td><span class="badge ${r.enabled !== false ? 'badge-success' : 'badge-danger'}">${r.enabled !== false ? 'Enabled' : 'Disabled'}</span></td>
                            <td>
                                <div style="display: flex; gap: 4px;">
                                    <button class="btn btn-sm btn-outline" onclick="Settings.toggleRule(${i})">${r.enabled !== false ? 'Disable' : 'Enable'}</button>
                                    <button class="btn btn-sm btn-danger" onclick="Settings.removeRule(${i})">Remove</button>
                                </div>
                            </td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        `;
    }

    async function saveConfig() {
        const editor = document.getElementById('config-editor');
        const errorEl = document.getElementById('config-error');
        if (!editor) return;

        const text = editor.value.trim();
        try {
            const parsed = JSON.parse(text);
            errorEl.style.display = 'none';

            await App.api('POST', '/config', parsed);
            config = parsed;
            Toast.show('Configuration saved successfully', 'success');

            const rulesTable = document.getElementById('rules-table');
            if (rulesTable) rulesTable.innerHTML = renderRulesTable();
        } catch (err) {
            if (err instanceof SyntaxError) {
                errorEl.textContent = `JSON Error: ${err.message}`;
                errorEl.style.display = 'block';
                Toast.show('Invalid JSON - check syntax', 'error');
            } else {
                Toast.show('Failed to save configuration: ' + err.message, 'error');
            }
        }
    }

    async function reloadConfig() {
        try {
            config = await App.api('GET', '/config');
            const editor = document.getElementById('config-editor');
            if (editor) editor.value = JSON.stringify(config || {}, null, 2);
            Toast.show('Configuration reloaded', 'success');
        } catch (err) {
            Toast.show('Failed to reload configuration', 'error');
        }
    }

    function addRule() {
        if (!config) config = {};
        if (!config.rules && !config.detectionRules) config.detectionRules = [];
        const rulesKey = config.rules ? 'rules' : 'detectionRules';
        config[rulesKey].push({
            name: 'New Rule',
            severity: 'medium',
            enabled: true,
            pattern: '',
            description: '',
        });
        syncEditor();
        const rulesTable = document.getElementById('rules-table');
        if (rulesTable) rulesTable.innerHTML = renderRulesTable();
        Toast.show('New rule added - edit config to customize', 'info');
    }

    function toggleRule(index) {
        const rulesKey = config?.rules ? 'rules' : 'detectionRules';
        const rules = config?.[rulesKey];
        if (!rules || !rules[index]) return;
        rules[index].enabled = !rules[index].enabled;
        syncEditor();
        const rulesTable = document.getElementById('rules-table');
        if (rulesTable) rulesTable.innerHTML = renderRulesTable();
    }

    function removeRule(index) {
        if (!confirm('Remove this rule?')) return;
        const rulesKey = config?.rules ? 'rules' : 'detectionRules';
        const rules = config?.[rulesKey];
        if (!rules || !rules[index]) return;
        rules.splice(index, 1);
        syncEditor();
        const rulesTable = document.getElementById('rules-table');
        if (rulesTable) rulesTable.innerHTML = renderRulesTable();
        Toast.show('Rule removed', 'success');
    }

    function syncEditor() {
        const editor = document.getElementById('config-editor');
        if (editor) editor.value = JSON.stringify(config || {}, null, 2);
    }

    return { init, render, saveConfig, reloadConfig, addRule, toggleRule, removeRule };
})();
