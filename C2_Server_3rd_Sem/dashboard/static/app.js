/**
 * SecureComm Dashboard v3.0 - Enterprise C2 Interface
 * Real-time monitoring, command orchestration, and analytics with advanced features
 *
 * NEW FEATURES v3.0:
 * - Complete payload builder with encryption visualization
 * - File manager with upload/download capabilities
 * - PKI certificate inspector
 * - Batch command execution
 * - Command templates library
 * - Advanced search and filtering
 * - Real-time validation
 *
 * Author: Shadow Junior
 * Version: 3.0.0 - Academic Production Release
 */

class SecureCommDashboard {
    constructor() {
        this.apiBase = '/api';
        this.wsUrl = `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}/ws`;
        this.token = window.DASHBOARD_TOKEN || this.getToken();
        this.autoRefresh = true;
        this.refreshInterval = window.AUTO_REFRESH_INTERVAL || 5000;
        this.refreshTimer = null;
        this.ws = null;
        this.wsReconnectAttempts = 0;
        this.maxWsReconnectAttempts = 5;
        this.wsReconnectDelay = 3000;
        this.currentPage = 'dashboard';
        this.agents = [];
        this.commands = [];
        this.stats = {};
        this.selectedAgents = new Set();

        // NEW: Enhanced state
        this.certificates = [];
        this.files = [];
        this.templates = {};
        this.currentAgent = null;
        this.searchQuery = '';
        this.statusFilter = 'all';

        this.init();
    }

    init() {
        this.bindEvents();
        this.initWebSocket();
        this.loadData();
        this.startAutoRefresh();
        this.updateConnectionStatus('connected');
    }

    // ==================== TOKEN & AUTH ====================

    getToken() {
        const urlParams = new URLSearchParams(window.location.search);
        const token = urlParams.get('token');
        if (token) {
            sessionStorage.setItem('securecomm_token', token);
            return token;
        }
        return sessionStorage.getItem('securecomm_token') || '';
    }

    getHeaders() {
        const headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        };
        if (this.token) {
            headers['Authorization'] = `Bearer ${this.token}`;
        }
        return headers;
    }

    // ==================== WEBSOCKET ====================

    initWebSocket() {
        if (!this.token) return;

        try {
            this.ws = new WebSocket(`${this.wsUrl}?token=${this.token}`);

            this.ws.onopen = () => {
                console.log('WebSocket connected');
                this.wsReconnectAttempts = 0;
                this.updateConnectionStatus('connected');
                this.showToast('Real-time updates enabled', 'success');
            };

            this.ws.onmessage = (event) => {
                try {
                    const message = JSON.parse(event.data);
                    this.handleWebSocketMessage(message);
                } catch (e) {
                    console.error('WebSocket message parse error:', e);
                }
            };

            this.ws.onclose = () => {
                console.log('WebSocket disconnected');
                this.updateConnectionStatus('disconnected');
                this.attemptWebSocketReconnect();
            };

            this.ws.onerror = (error) => {
                console.error('WebSocket error:', error);
                this.updateConnectionStatus('error');
            };

        } catch (e) {
            console.error('WebSocket initialization failed:', e);
        }
    }

    attemptWebSocketReconnect() {
        if (this.wsReconnectAttempts >= this.maxWsReconnectAttempts) {
            console.log('Max WebSocket reconnect attempts reached');
            this.showToast('Real-time updates disabled. Using polling.', 'warning');
            return;
        }

        this.wsReconnectAttempts++;
        console.log(`Attempting WebSocket reconnect ${this.wsReconnectAttempts}/${this.maxWsReconnectAttempts}`);

        setTimeout(() => {
            this.initWebSocket();
        }, this.wsReconnectDelay);
    }

    handleWebSocketMessage(message) {
        switch (message.type) {
            case 'command_sent':
                this.showToast(`Command sent to ${message.data.agent_id}`, 'success');
                this.loadData();
                break;
            case 'agent_connected':
                this.showToast(`Agent ${message.data.agent_id} connected`, 'success');
                this.loadData();
                break;
            case 'agent_disconnected':
                this.showToast(`Agent ${message.data.agent_id} disconnected`, 'warning');
                this.loadData();
                break;
            case 'command_completed':
                this.showToast(`Command ${message.data.task_id} completed`, 'info');
                this.loadData();
                break;
            case 'batch_command_sent':
                this.showToast(`Batch command sent to ${message.data.agents_count} agents`, 'success');
                this.loadData();
                break;
            case 'security_event':
                this.showToast(`Security event: ${message.data.event}`, 'error');
                break;
            case 'ping':
            case 'pong':
                break;
            default:
                console.log('Unknown WebSocket message:', message);
        }
    }

    sendWebSocketMessage(message) {
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            this.ws.send(JSON.stringify(message));
        }
    }

    // ==================== EVENT BINDING ====================

    bindEvents() {
        console.log('🔧 Binding events...');

        // Simple direct event binding without cloning
        const bindButton = (buttonId, handler, description) => {
            const button = document.getElementById(buttonId);
            if (button) {
                button.addEventListener('click', (e) => {
                    console.log(`🔧 ${description} button clicked!`);
                    e.preventDefault();
                    e.stopPropagation();
                    handler.call(this, e);
                });
                console.log(`✅ ${description} button bound`);
                return true;
            } else {
                console.warn(`⚠️ ${description} button (${buttonId}) not found`);
                return false;
            }
        };

        // Bind all buttons directly
        bindButton('btn-new-command', this.openCommandModal, 'New Command');
        bindButton('btn-payload-builder', this.openPayloadBuilder, 'Payload Builder');
        bindButton('btn-file-manager', this.openFileManager, 'File Manager');
        bindButton('btn-cert-viewer', this.openCertificateViewer, 'Certificate Viewer');
        bindButton('btn-batch-command', this.executeBatchCommand, 'Batch Command');
        bindButton('refresh-btn', this.refreshData, 'Refresh');

        // Navigation
        try {
            document.querySelectorAll('.nav-link').forEach(link => {
                link.addEventListener('click', (e) => {
                    document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
                    e.target.closest('.nav-link').classList.add('active');
                });
            });
            console.log('✅ Navigation links bound');
        } catch (error) {
            console.error('❌ Failed to bind navigation links:', error);
        }

        const autoRefreshToggle = document.getElementById('auto-refresh');
        if (autoRefreshToggle) {
            autoRefreshToggle.addEventListener('change', (e) => {
                this.autoRefresh = e.target.checked;
                if (this.autoRefresh) {
                    this.startAutoRefresh();
                    this.showToast('Auto-refresh enabled', 'info');
                } else {
                    this.stopAutoRefresh();
                    this.showToast('Auto-refresh disabled', 'info');
                }
            });
            console.log('✅ Auto-refresh toggle bound');
        } else {
            console.log('❌ Auto-refresh toggle not found');
        }

        try {
            document.querySelectorAll('.modal-close').forEach(closeBtn => {
                closeBtn.addEventListener('click', () => this.closeCommandModal());
            });
            console.log('✅ Modal close buttons bound');
        } catch (error) {
            console.error('❌ Failed to bind modal close buttons:', error);
        }

        // Modal background click to close
        const modal = document.getElementById('command-modal');
        if (modal) {
            modal.addEventListener('click', (e) => {
                if (e.target === modal) this.closeCommandModal();
            });
            console.log('✅ Modal background click bound');
        } else {
            console.log('❌ Command modal not found');
        }

        // Command form submission
        const commandForm = document.getElementById('command-form');
        if (commandForm) {
            commandForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.handleCommandSubmit(e);
            });
            console.log('✅ Command form bound');
        } else {
            console.log('❌ Command form not found');
        }

        // Command type change handler (toggles payload/path fields)
        const cmdTypeSelect = document.getElementById('cmd-type');
        if (cmdTypeSelect) {
            cmdTypeSelect.addEventListener('change', (e) => {
                this.handleCommandTypeChange(e.target.value);
            });
            console.log('✅ Command type change bound');
        }

        // NEW: Search functionality
        const searchInput = document.getElementById('search-input');
        if (searchInput) {
            searchInput.addEventListener('input', (e) => {
                this.searchQuery = e.target.value.toLowerCase();
                this.filterAndRenderAgents();
            });
        }

        // NEW: Status filter
        const statusFilter = document.getElementById('status-filter');
        if (statusFilter) {
            statusFilter.addEventListener('change', (e) => {
                this.statusFilter = e.target.value;
                this.filterAndRenderAgents();
            });
        }
    }

    // ==================== DATA LOADING ====================

    async loadData() {
        this.updateConnectionStatus('loading');

        try {
            const [stateResponse, statsResponse] = await Promise.all([
                fetch(`${this.apiBase}/state`, { headers: this.getHeaders() }),
                fetch(`${this.apiBase}/stats`, { headers: this.getHeaders() })
            ]);

            if (!stateResponse.ok || !statsResponse.ok) {
                throw new Error('Failed to fetch data');
            }

            const state = await stateResponse.json();
            const stats = await statsResponse.json();

            this.agents = state.agents || [];
            this.commands = state.commands || [];
            this.stats = stats;

            this.renderDashboard();
            this.updateLastRefresh();
            this.updateConnectionStatus('connected');

        } catch (error) {
            console.error('Error loading data:', error);
            this.updateConnectionStatus('error');
            this.showToast('Failed to load data', 'error');
        }
    }

    // NEW: Load additional data
    async loadCertificates() {
        try {
            const response = await fetch(`${this.apiBase}/certificates`, {
                headers: this.getHeaders()
            });

            if (!response.ok) throw new Error('Failed to fetch certificates');

            const data = await response.json();
            this.certificates = data.certificates || [];
            return this.certificates;

        } catch (error) {
            console.error('Error loading certificates:', error);
            this.showToast('Failed to load certificates', 'error');
            return [];
        }
    }

    // NEW: Load agent files
    async loadAgentFiles(agentId) {
        try {
            const response = await fetch(`${this.apiBase}/files/browse?agent_id=${agentId}`, {
                headers: this.getHeaders()
            });

            if (!response.ok) throw new Error('Failed to fetch files');

            const data = await response.json();
            this.files = data.files || [];
            return this.files;

        } catch (error) {
            console.error('Error loading files:', error);
            this.showToast('Failed to load files', 'error');
            return [];
        }
    }

    // NEW: Load payload templates
    async loadPayloadTemplates() {
        try {
            const response = await fetch(`${this.apiBase}/payload/templates`, {
                headers: this.getHeaders()
            });

            if (!response.ok) throw new Error('Failed to fetch templates');

            const data = await response.json();
            // Convert array to object keyed by template ID
            const templatesArray = data.templates || [];
            this.templates = {};
            templatesArray.forEach(template => {
                if (template.id) {
                    this.templates[template.id] = template;
                }
            });
            return this.templates;

        } catch (error) {
            console.error('Error loading templates:', error);
            this.showToast('Failed to load templates', 'error');
            return {};
        }
    }

    // ==================== RENDERING ====================

    renderDashboard() {
        this.renderStats();
        this.renderAgents();
        this.renderCommands();
        this.renderDashboardActivity();
    }

    renderStats() {
        // Update stat cards
        const statElements = {
            'stat-total-agents': this.stats.total_agents || 0,
            'stat-active-agents': this.stats.active_agents || 0,
            'stat-total-commands': this.stats.total_commands || 0,
            'stat-pending-commands': this.stats.pending_commands || 0,
            'stat-successful-commands': this.stats.successful_commands || 0,
            'stat-failed-commands': this.stats.failed_commands || 0,
            'stat-success-rate': this.calculateSuccessRate(),
            'stat-uptime': this.formatUptime(this.stats.uptime_seconds || 0)
        };

        for (const [id, value] of Object.entries(statElements)) {
            const el = document.getElementById(id);
            if (el) el.textContent = value;
        }

        // NEW: Enhanced stats
        const dataTransferred = document.getElementById('stat-data-transferred');
        if (dataTransferred) {
            dataTransferred.textContent = `${(this.stats.data_transferred_mb || 0).toFixed(2)} MB`;
        }

        const avgResponseTime = document.getElementById('stat-avg-response-time');
        if (avgResponseTime) {
            avgResponseTime.textContent = `${(this.stats.avg_response_time_ms || 0).toFixed(0)} ms`;
        }
    }

    renderAgents() {
        const tbody = document.getElementById('agents-tbody');
        if (!tbody) return;

        if (this.agents.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="empty-hint">No agents connected</td></tr>';
            return;
        }

        // Apply filters
        let filteredAgents = this.filterAgents();

        tbody.innerHTML = filteredAgents.map(agent => `
        <tr data-agent-id="${this.escapeHtml(agent.agent_id)}">
        <td>
        <input type="checkbox" class="agent-select"
        ${this.selectedAgents.has(agent.agent_id) ? 'checked' : ''}
        onchange="dashboard.toggleAgentSelection('${this.escapeHtml(agent.agent_id)}', this.checked)">
        </td>
        <td><code class="agent-id">${this.escapeHtml(agent.agent_id)}</code></td>
        <td>${this.escapeHtml(agent.ip_address || '-')}</td>
        <td><span class="status-badge status-${agent.status}">${this.escapeHtml(agent.status)}</span></td>
        <td>${this.formatTimestamp(agent.connected_at)}</td>
        <td>${this.formatRelativeTime(agent.last_seen)}</td>
        <td>
        <div class="action-buttons">
        <button class="btn btn-sm btn-primary" onclick="dashboard.sendCommandTo('${this.escapeHtml(agent.agent_id)}')">
        Command
        </button>
        <button class="btn btn-sm btn-info" onclick="dashboard.viewAgentDetails('${this.escapeHtml(agent.agent_id)}')">
        Details
        </button>
        <button class="btn btn-sm btn-secondary" onclick="dashboard.openFileManager('${this.escapeHtml(agent.agent_id)}')">
        Files
        </button>
        </div>
        </td>
        </tr>
        `).join('');
    }

    renderCommands() {
        const tbody = document.getElementById('commands-tbody');
        if (!tbody) return;

        if (this.commands.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="empty-hint">No commands issued</td></tr>';
            return;
        }

        tbody.innerHTML = this.commands.slice(0, 20).map(cmd => `
        <tr>
        <td><code class="task-id">${this.truncate(cmd.task_id, 12)}</code></td>
        <td><code>${this.escapeHtml(cmd.agent_id)}</code></td>
        <td><span class="type-badge">${this.escapeHtml(cmd.command_type)}</span></td>
        <td><span class="status-badge status-${cmd.status}">${this.escapeHtml(cmd.status)}</span></td>
        <td>${this.formatRelativeTime(cmd.created_at)}</td>
        <td>${this.truncate(cmd.payload, 40)}</td>
        </tr>
        `).join('');
    }

    // Render recent activity on the Dashboard page
    renderDashboardActivity() {
        const tbody = document.getElementById('dashboard-activity-tbody');
        if (!tbody) return;

        // Use the most recent commands as activity feed
        const recentCommands = this.commands.slice(0, 10);

        if (recentCommands.length === 0) {
            tbody.innerHTML = `<tr>
                <td colspan="4" class="empty-hint">
                    <div style="text-align: center; padding: 2rem;">
                        <div style="font-size: 3rem;">⚡</div>
                        <div>No recent activity</div>
                    </div>
                </td>
            </tr>`;
            return;
        }

        tbody.innerHTML = recentCommands.map(cmd => `
        <tr>
        <td>${this.formatRelativeTime(cmd.created_at)}</td>
        <td><code>${this.escapeHtml(cmd.agent_id)}</code></td>
        <td><span class="type-badge">${this.escapeHtml(cmd.command_type)}</span></td>
        <td><span class="status-badge status-${cmd.status}">${this.escapeHtml(cmd.status)}</span></td>
        </tr>
        `).join('');
    }

    // NEW: Filter agents based on search and status
    filterAgents() {
        return this.agents.filter(agent => {
            // Status filter
            if (this.statusFilter !== 'all' && agent.status !== this.statusFilter) {
                return false;
            }

            // Search filter
            if (this.searchQuery) {
                const searchLower = this.searchQuery.toLowerCase();
                return (
                    agent.agent_id.toLowerCase().includes(searchLower) ||
                    (agent.ip_address || '').toLowerCase().includes(searchLower) ||
                    (agent.certificate_subject || '').toLowerCase().includes(searchLower)
                );
            }

            return true;
        });
    }

    filterAndRenderAgents() {
        this.renderAgents();
    }

    // ==================== COMMAND HANDLING ====================

    openCommandModal(agentId = null) {
        // Use persistent modal
        const modal = document.getElementById('command-modal');
        const modalBody = document.getElementById('command-modal-body');
        
        if (!modal || !modalBody) {
            console.error('Command modal not found');
            return;
        }

        // Populate modal content
        modalBody.innerHTML = `
            <form id="command-form" onsubmit="dashboard.handleCommandSubmit(event)">
                <div class="form-group">
                    <label>Target Agent</label>
                    <select id="cmd-agent" class="form-control">
                        ${this.agents.map(a => `
                            <option value="${this.escapeHtml(a.agent_id)}" ${a.agent_id === agentId ? 'selected' : ''}>
                                ${this.escapeHtml(a.agent_id)}
                            </option>
                        `).join('')}
                    </select>
                </div>
                <div class="form-group">
                    <label>Command Type</label>
                    <select id="cmd-type" class="form-control" onchange="dashboard.handleCommandTypeChange(this.value)">
                        <option value="exec">Execute</option>
                        <option value="shell">Shell</option>
                        <option value="upload">Upload File</option>
                        <option value="download">Download File</option>
                        <option value="info">System Info</option>
                        <option value="recon">Reconnaissance</option>
                    </select>
                </div>
                <div class="form-group" id="cmd-payload-group">
                    <label>Command Payload</label>
                    <textarea id="cmd-payload" class="form-control" rows="4" placeholder="Enter command payload..."></textarea>
                </div>
                <div class="form-group" id="cmd-path-group" style="display: none;">
                    <label>File Path</label>
                    <input type="text" id="cmd-path" class="form-control" placeholder="/path/to/file">
                </div>
                <div class="form-actions">
                    <button type="button" class="btn btn-secondary" onclick="dashboard.closeCommandModal()">Cancel</button>
                    <button type="submit" class="btn btn-primary">Send Command</button>
                </div>
            </form>
        `;

        // Show the modal
        modal.classList.add('active');
        modal.style.display = 'flex';
    }

    closeCommandModal() {
        const modal = document.getElementById('command-modal');
        if (modal) {
            modal.classList.remove('active');
            modal.style.display = 'none';
        }
    }

    closeModal(modalId) {
        const modal = document.getElementById(modalId);
        if (modal) {
            modal.classList.remove('active');
            modal.style.display = 'none';
        }
    }

    handleCommandTypeChange(type) {
        const payloadGroup = document.getElementById('cmd-payload-group');
        const pathGroup = document.getElementById('cmd-path-group');

        if (!payloadGroup || !pathGroup) return;

        if (type === 'upload' || type === 'download') {
            payloadGroup.style.display = 'none';
            pathGroup.style.display = 'block';
        } else {
            payloadGroup.style.display = 'block';
            pathGroup.style.display = 'none';
        }
    }

    async handleCommandSubmit(e) {
        e.preventDefault();

        const form = e.target;
        const agentId = form.querySelector('#cmd-agent').value;
        const cmdType = form.querySelector('#cmd-type').value;

        let payload;
        if (cmdType === 'upload' || cmdType === 'download') {
            payload = form.querySelector('#cmd-path').value;
        } else {
            payload = form.querySelector('#cmd-payload').value;
        }

        this.closeCommandModal();

        try {
            const response = await fetch(`${this.apiBase}/command`, {
                method: 'POST',
                headers: this.getHeaders(),
                body: JSON.stringify({
                    agent_id: agentId,
                    type: cmdType,
                    payload: payload
                })
            });

            const result = await response.json();

            if (!response.ok) {
                throw new Error(result.error || 'Command failed');
            }

            this.showToast(`Command sent successfully (Task ID: ${result.task_id})`, 'success');
            this.loadData();

        } catch (error) {
            console.error('Command error:', error);
            this.showToast(`Command failed: ${error.message}`, 'error');
        }
    }

    sendCommandTo(agentId) {
        this.openCommandModal(agentId);
    }

    // NEW: Toggle agent selection
    toggleAgentSelection(agentId, selected) {
        if (selected) {
            this.selectedAgents.add(agentId);
        } else {
            this.selectedAgents.delete(agentId);
        }

        // Update batch command button state
        const batchBtn = document.getElementById('btn-batch-command');
        if (batchBtn) {
            batchBtn.disabled = this.selectedAgents.size === 0;
            batchBtn.textContent = this.selectedAgents.size > 0
                ? `Batch Command (${this.selectedAgents.size})`
                : 'Batch Command';
        }
    }

    handleSelectAll(checked) {
        document.querySelectorAll('.agent-select').forEach(cb => {
            cb.checked = checked;
            const agentId = cb.closest('tr')?.dataset.agentId;
            if (agentId) {
                if (checked) this.selectedAgents.add(agentId);
                else this.selectedAgents.delete(agentId);
            }
        });

        // Update batch button
        this.toggleAgentSelection('', false);
    }

    // NEW: Execute batch command
    async executeBatchCommand() {
        if (this.selectedAgents.size === 0) {
            this.showToast('No agents selected', 'warning');
            return;
        }

        const cmdType = prompt('Enter command type (exec/shell/status/info):');
        if (!cmdType) return;

        const payload = prompt('Enter command payload:');
        if (!payload) return;

        if (!confirm(`Execute ${cmdType} on ${this.selectedAgents.size} agents?`)) {
            return;
        }

        try {
            const response = await fetch(`${this.apiBase}/command/batch`, {
                method: 'POST',
                headers: this.getHeaders(),
                body: JSON.stringify({
                    agent_ids: Array.from(this.selectedAgents),
                    type: cmdType,
                    payload: payload
                })
            });

            const result = await response.json();

            if (!response.ok) {
                throw new Error(result.error || 'Batch command failed');
            }

            const summary = result.summary || {};
            this.showToast(
                `Batch command: ${summary.successful || 0} successful, ${summary.failed || 0} failed`,
                summary.successful > 0 ? 'success' : 'error'
            );

            // Clear selection
            this.selectedAgents.clear();
            this.loadData();

        } catch (error) {
            console.error('Batch command error:', error);
            this.showToast(`Batch command failed: ${error.message}`, 'error');
        }
    }

    // ==================== NEW: PAYLOAD BUILDER ====================

    async openPayloadBuilder() {
        // Load templates
        await this.loadPayloadTemplates();

        // Use persistent modal
        const modal = document.getElementById('payload-builder-modal');
        const modalBody = document.getElementById('payload-builder-body');
        
        if (!modal || !modalBody) {
            console.error('Payload builder modal not found');
            return;
        }

        // Populate modal content
        modalBody.innerHTML = `
        <div class="payload-builder-grid">
        <div class="builder-section">
        <h4>Configuration</h4>
        <div class="form-group">
        <label>Agent</label>
        <select id="payload-agent">
        ${this.agents.map(a => `
            <option value="${this.escapeHtml(a.agent_id)}">
            ${this.escapeHtml(a.agent_id)} (${this.escapeHtml(a.ip_address || 'unknown')})
            </option>
            `).join('')}
            </select>
            </div>
            <div class="form-group">
            <label>Command Type</label>
            <select id="payload-type">
            <option value="exec">Execute</option>
            <option value="shell">Shell</option>
            <option value="upload">Upload</option>
            <option value="download">Download</option>
            <option value="persist">Persist</option>
            <option value="recon">Recon</option>
            </select>
            </div>
            <div class="form-group">
            <label>Command Data</label>
            <textarea id="payload-data" rows="6" placeholder="Enter command data..."></textarea>
            </div>
            <button class="btn btn-primary" onclick="dashboard.buildPayload()">
            🔐 Build Encrypted Payload
            </button>
            </div>

            <div class="builder-section">
            <h4>Templates</h4>
            <div class="template-list">
            ${Object.entries(this.templates).map(([name, template]) => `
                <div class="template-item" onclick="dashboard.applyTemplate('${name}')">
                <div class="template-header">
                <strong>${this.escapeHtml(template.name)}</strong>
                <span class="risk-badge risk-${template.risk_level || 'medium'}">
                ${template.risk_level || 'medium'}
                </span>
                </div>
                <p class="template-desc">${this.escapeHtml(template.description)}</p>
                <div class="template-meta">
                ${template.commands_count} commands
                ${template.requires_admin ? '⚠️ Admin' : ''}
                </div>
                </div>
                `).join('')}
                </div>
                </div>
                </div>

                <div class="payload-result" id="payload-result" style="display: none;">
                <h4>Encrypted Payload</h4>
                <div class="payload-details">
                <div class="detail-row">
                <span>Algorithm:</span>
                <code id="payload-algorithm">-</code>
                </div>
                <div class="detail-row">
                <span>Size:</span>
                <code id="payload-size">-</code>
                </div>
                <div class="detail-row">
                <span>Timestamp:</span>
                <code id="payload-timestamp">-</code>
                </div>
                </div>
                <textarea id="payload-output" readonly rows="10"></textarea>
                <div class="button-group">
                <button class="btn btn-secondary" onclick="dashboard.copyPayload()">📋 Copy</button>
                <button class="btn btn-primary" onclick="dashboard.deployPayload()">🚀 Deploy</button>
                </div>
                </div>
        `;

        // Show the modal
        modal.classList.add('active');
        modal.style.display = 'flex';
    }

    async buildPayload() {
        const agentId = document.getElementById('payload-agent')?.value;
        const cmdType = document.getElementById('payload-type')?.value;
        const cmdData = document.getElementById('payload-data')?.value;

        if (!agentId || !cmdType || !cmdData) {
            this.showToast('All fields are required', 'warning');
            return;
        }

        try {
            const response = await fetch(`${this.apiBase}/payload/build`, {
                method: 'POST',
                headers: this.getHeaders(),
                body: JSON.stringify({
                    agent_id: agentId,
                    command_type: cmdType,
                    command_data: cmdData
                })
            });

            const result = await response.json();

            if (!response.ok) {
                throw new Error(result.error || 'Payload build failed');
            }

            // Store payload for deployment
            this.currentPayload = result.payload;
            this.currentPayloadAgent = agentId;

            // Display result
            const resultSection = document.getElementById('payload-result');
            if (resultSection) {
                resultSection.style.display = 'block';

                document.getElementById('payload-algorithm').textContent = result.metadata.encryption;
                document.getElementById('payload-size').textContent = `${result.metadata.payload_size_bytes} bytes`;
                document.getElementById('payload-timestamp').textContent = result.metadata.timestamp;
                document.getElementById('payload-output').value = JSON.stringify(result.payload, null, 2);

                // Show file path if available
                if (result.metadata.file_path) {
                    this.currentPayloadPath = result.metadata.file_path;
                    this.showToast(`Payload saved to: ${this.currentPayloadPath}`, 'success');
                }
            }


        } catch (error) {
            console.error('Payload build error:', error);
            this.showToast(`Payload build failed: ${error.message}`, 'error');
        }
    }

    applyTemplate(templateName) {
        // Load template details and populate form
        this.showToast(`Template "${templateName}" loaded (implementation pending)`, 'info');
    }

    copyPayload() {
        const output = document.getElementById('payload-output');
        if (output) {
            output.select();
            document.execCommand('copy');
            this.showToast('Payload copied to clipboard', 'success');
        }
    }

    async deployPayload() {
        if (!this.currentPayload || !this.currentPayloadAgent) {
            this.showToast('No payload to deploy', 'warning');
            return;
        }

        if (!confirm(`Deploy payload to agent ${this.currentPayloadAgent}?`)) {
            return;
        }

        // Implementation: Send the encrypted payload as a command
        // For now, we just show where the payload is saved
        const msg = this.currentPayloadPath
            ? `Payload is saved at:\n${this.currentPayloadPath}\n\nTransfer this file to the target agent manually or via the 'Upload File' command.`
            : 'Payload metadata is ready. Transfer the JSON content to the target.';

        alert(`🚀 Deployment Instructions:\n\n${msg}`);
    }

    // ==================== NEW: AGENT BUILDER ====================

    async openAgentBuilder() {
        // Use persistent modal
        const modal = document.getElementById('agent-builder-modal');
        const modalBody = document.getElementById('agent-builder-body');
        
        if (!modal || !modalBody) {
            console.error('Agent builder modal not found');
            return;
        }

        // Populate modal content
        modalBody.innerHTML = `
        <div class="agent-builder-form">
        <div class="form-group">
        <label>Agent ID</label>
        <input type="text" id="build-agent-id" placeholder="e.g., demo_agent_01" value="demo_agent_${Date.now().toString().slice(-4)}">
        </div>
        <div class="form-group">
        <label>C2 Server IP</label>
        <input type="text" id="build-agent-server" placeholder="e.g., 192.168.1.100" value="${window.location.hostname}">
        </div>
        <div class="form-group">
        <label>C2 Server Port</label>
        <input type="number" id="build-agent-port" value="8443">
        </div>
        <div class="form-group">
        <label>Platform</label>
        <select id="build-agent-platform">
        <option value="windows">Windows (.exe)</option>
        <option value="linux">Linux (binary)</option>
        </select>
        </div>
        <div class="form-notice">
        <strong>⚠️ Prerequisites:</strong>
        <p class="notice-text">Agent certificates must be generated first:</p>
        <code class="command-code">python launcher.py issue-cert --common-name &lt;agent-id&gt; --type agent</code>
        </div>
        <button class="btn btn-primary btn-lg" onclick="dashboard.buildAgent()">
        🔨 Build Agent Package
        </button>
        </div>

        <div class="agent-build-result" id="agent-build-result" style="display: none;">
        <h4>Build Result</h4>
        <div class="build-details">
        <div class="detail-row"><span>Status:</span> <span id="build-status" style="color: var(--status-success);">-</span></div>
        <div class="detail-row"><span>Agent ID:</span> <code id="build-result-agent-id">-</code></div>
        <div class="detail-row"><span>Platform:</span> <code id="build-result-platform">-</code></div>
        <div class="detail-row"><span>Server:</span> <code id="build-result-server">-</code></div>
        <div class="detail-row"><span>Config:</span> <code id="build-result-config">-</code></div>
        <div class="detail-row"><span>Executable:</span> <code id="build-result-exe">-</code></div>
        <div class="detail-row"><span>Package:</span> <code id="build-result-package">-</code></div>
        </div>
        <div class="build-actions">
        <a id="agent-download-link" href="#" class="btn btn-success" style="display: none;">📦 Download Package</a>
        <button class="btn btn-secondary" onclick="dashboard.closeModal('agent-builder-modal')">Close</button>
        </div>
        </div>
        </div>
        `;

        // Show the modal
        modal.classList.add('active');
        modal.style.display = 'flex';
    }

    async buildAgent() {
        const agentId = document.getElementById('build-agent-id')?.value;
        const server = document.getElementById('build-agent-server')?.value;
        const port = parseInt(document.getElementById('build-agent-port')?.value) || 8443;
        const platform = document.getElementById('build-agent-platform')?.value || 'windows';

        if (!agentId || !server) {
            this.showToast('Agent ID and Server IP are required', 'warning');
            return;
        }

        this.showToast('Building agent package... This may take a minute.', 'info');

        try {
            const response = await fetch(`${this.apiBase}/agent/build`, {
                method: 'POST',
                headers: this.getHeaders(),
                body: JSON.stringify({
                    agent_id: agentId,
                    server: server,
                    port: port,
                    platform: platform
                })
            });

            const result = await response.json();

            if (!response.ok) {
                throw new Error(result.error || result.detail || 'Agent build failed');
            }

            // Show result
            const resultSection = document.getElementById('agent-build-result');
            if (resultSection) {
                resultSection.style.display = 'block';
                document.getElementById('build-status').textContent = '✅ Success';
                document.getElementById('build-result-agent-id').textContent = result.agent_id;
                document.getElementById('build-result-platform').textContent = result.platform;
                document.getElementById('build-result-server').textContent = `${result.server}:${result.port}`;
                document.getElementById('build-result-config').textContent = result.config_path;
                document.getElementById('build-result-exe').textContent = result.executable_path || 'N/A';
                document.getElementById('build-result-package').textContent = result.package_dir;

                // Set download link
                const downloadLink = document.getElementById('agent-download-link');
                if (downloadLink && result.download_url) {
                    downloadLink.href = result.download_url;
                    downloadLink.style.display = 'inline-block';
                }
            }

            this.showToast(`Agent ${result.agent_id} built successfully!`, 'success');

        } catch (error) {
            console.error('Agent build error:', error);
            this.showToast(`Agent build failed: ${error.message}`, 'error');

            // Show error in result section
            const resultSection = document.getElementById('agent-build-result');
            if (resultSection) {
                resultSection.style.display = 'block';
                document.getElementById('build-status').textContent = '❌ Failed';
                document.getElementById('build-status').style.color = '#ff4444';
            }
        }
    }

    // ==================== NEW: ADVANCED FILE MANAGER ====================

    async openFileManager(agentId = null) {
        if (!agentId && this.agents.length > 0) {
            agentId = this.agents[0].agent_id;
        }

        if (!agentId) {
            this.showToast('No agents available', 'warning');
            return;
        }

        // Initialize advanced file manager state
        this.fileManagerState = {
            currentAgent: agentId,
            selectedFiles: new Set(),
            clipboardFiles: new Set(),
            operationQueue: [],
            activeOperations: new Map(),
            dragState: {
                isDragging: false,
                draggedFiles: [],
                dropTarget: null
            }
        };

        // Load files
        await this.loadAgentFiles(agentId);

        // Create advanced file manager modal
        const modal = document.createElement('div');
        modal.className = 'modal';
        modal.id = 'file-manager-modal';
        modal.innerHTML = `
        <div class="modal-content file-manager-modal">
            <div class="modal-header">
                <h3>📁 Advanced File Manager - ${this.escapeHtml(agentId)}</h3>
                <div class="header-actions">
                    <button class="btn btn-sm btn-secondary" onclick="dashboard.toggleFileManagerView()">
                        <span id="view-toggle-icon">📋</span> <span id="view-toggle-text">Details</span>
                    </button>
                    <button class="btn btn-sm btn-info" onclick="dashboard.refreshFileManager()">
                        🔄 Refresh
                    </button>
                    <button class="btn btn-sm btn-primary" onclick="dashboard.uploadMultipleFiles()">
                        ⬆️ Upload Multiple
                    </button>
                </div>
                <button class="modal-close" onclick="this.closest('.modal').remove()">&times;</button>
            </div>
            <div class="modal-body">
                <!-- Toolbar Row 1: Agent & Search -->
                <div class="file-manager-toolbar-row">
                    <div class="toolbar-left">
                        <div class="form-group">
                            <label>Agent:</label>
                            <select id="file-manager-agent" onchange="dashboard.switchFileManagerAgent(this.value)">
                                ${this.agents.map(a => `
                                    <option value="${this.escapeHtml(a.agent_id)}" ${a.agent_id === agentId ? 'selected' : ''}>
                                        ${this.escapeHtml(a.agent_id)}
                                    </option>
                                `).join('')}
                            </select>
                        </div>
                    </div>
                    <div class="toolbar-center">
                        <div class="form-group search-group">
                            <input type="text" id="file-search" placeholder="🔍 Search files..." onkeyup="dashboard.searchFiles(this.value)">
                            <button class="btn btn-sm btn-secondary" onclick="dashboard.clearFileSearch()">Clear</button>
                        </div>
                    </div>
                    <div class="toolbar-right">
                        <div class="view-toggle">
                            <button class="btn btn-sm btn-icon active" onclick="dashboard.setFileView('list')" title="List View">📋 List</button>
                            <button class="btn btn-sm btn-icon" onclick="dashboard.setFileView('grid')" title="Grid View">⊞ Grid</button>
                            <button class="btn btn-sm btn-icon" onclick="dashboard.setFileView('tree')" title="Tree View">🌳 Tree</button>
                        </div>
                    </div>
                </div>

                <!-- Toolbar Row 2: Batch Operations -->
                <div class="file-manager-toolbar-row batch-row">
                    <div class="batch-operations">
                        <span class="batch-info">
                            <span id="selected-count">0</span> files selected
                        </span>
                        <button class="btn btn-sm btn-warning" id="delete-selected" onclick="dashboard.deleteSelectedFiles()" disabled>
                            🗑️ Delete
                        </button>
                        <button class="btn btn-sm btn-info" id="download-selected" onclick="dashboard.downloadSelectedFiles()" disabled>
                            ⬇️ Download
                        </button>
                        <button class="btn btn-sm btn-secondary" id="copy-selected" onclick="dashboard.copySelectedFiles()" disabled>
                            📋 Copy
                        </button>
                        <button class="btn btn-sm btn-primary" id="move-selected" onclick="dashboard.moveSelectedFiles()" disabled>
                            ✂️ Move
                        </button>
                        <button class="btn btn-sm btn-secondary" onclick="dashboard.toggleSelectAll()">
                            ☑️ Select All
                        </button>
                    </div>
                </div>

                <!-- Upload Area -->
                <div class="upload-section">
                    <div class="upload-area" id="upload-area" onclick="document.getElementById('file-input-multiple').click()" ondrop="dashboard.handleFileDrop(event)" ondragover="dashboard.handleDragOver(event)" ondragleave="dashboard.handleDragLeave(event)">
                        <div class="upload-content">
                            <div class="upload-icon">📁</div>
                            <div class="upload-text">
                                <strong>Drag & Drop files here</strong>
                                <span>or click to browse</span>
                            </div>
                        </div>
                        <input type="file" id="file-input-multiple" multiple style="display: none;" onchange="dashboard.handleMultipleFileSelect(event)">
                    </div>
                </div>

                <!-- File List -->
                <div class="file-list-container">
                    <table class="data-table file-table">
                        <thead>
                            <tr>
                                <th style="width: 40px;"><input type="checkbox" id="select-all-files" onclick="dashboard.toggleSelectAll()"></th>
                                <th>Name</th>
                                <th style="width: 80px;">Type</th>
                                <th style="width: 100px;">Size</th>
                                <th style="width: 150px;">Modified</th>
                                <th style="width: 100px;">Permissions</th>
                                <th style="width: 120px;">Actions</th>
                            </tr>
                        </thead>
                        <tbody id="file-manager-tbody">
                            ${this.renderAdvancedFileList()}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        `;

        document.body.appendChild(modal);
        modal.classList.add('active');
        modal.style.display = 'flex';

        // Setup drag and drop
        this.setupFileManagerDragDrop();
    }

    // ==================== ADVANCED FILE MANAGER METHODS ====================

    initializeFileManagerFeatures() {
        console.log('🔧 Initializing advanced file manager features...');

        // Setup drag and drop
        this.setupDragAndDrop();

        // Setup keyboard shortcuts
        this.setupFileKeyboardShortcuts();

        // Setup context menu
        this.setupFileContextMenu();

        console.log('✅ Advanced file manager features initialized');
    }

    setupDragAndDrop() {
        const dropZone = document.getElementById('upload-area');
        if (!dropZone) return;

        // Prevent default drag behaviors
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            dropZone.addEventListener(eventName, (e) => {
                e.preventDefault();
                e.stopPropagation();
            });
        });

        console.log('✅ Drag and drop setup complete');
    }

    handleFileDrop(event) {
        event.preventDefault();
        event.stopPropagation();

        const files = Array.from(event.dataTransfer.files);
        console.log(`📁 Dropped ${files.length} files`);

        if (files.length > 0) {
            this.uploadMultipleFiles(files);
        }
    }

    handleDragOver(event) {
        event.preventDefault();
        event.stopPropagation();

        const dropZone = document.getElementById('upload-area');
        if (dropZone) {
            dropZone.classList.add('drag-over');
        }
    }

    handleDragLeave(event) {
        event.preventDefault();
        event.stopPropagation();

        const dropZone = document.getElementById('upload-area');
        if (dropZone) {
            dropZone.classList.remove('drag-over');
        }
    }

    handleMultipleFileSelect(event) {
        const files = Array.from(event.target.files);
        console.log(`📁 Selected ${files.length} files for upload`);

        if (files.length > 0) {
            this.uploadMultipleFiles(files);
        }
    }

    async uploadMultipleFiles(files) {
        if (!this.fileManagerState.currentAgent) {
            this.showToast('No agent selected', 'warning');
            return;
        }

        console.log(`📤 Uploading ${files.length} files to agent ${this.fileManagerState.currentAgent}`);

        const progressContainer = document.getElementById('file-progress-container');
        const progressList = document.getElementById('progress-list');

        progressContainer.style.display = 'block';
        progressList.innerHTML = '';

        for (let i = 0; i < files.length; i++) {
            const file = files[i];
            const operationId = `upload_${Date.now()}_${i}`;

            // Create progress item
            const progressItem = document.createElement('div');
            progressItem.className = 'progress-item';
            progressItem.innerHTML = `
                <div class="progress-info">
                    <span class="progress-name">${this.escapeHtml(file.name)}</span>
                    <span class="progress-status">Uploading...</span>
                    <span class="progress-percentage">0%</span>
                </div>
                <div class="progress-bar">
                    <div class="progress-fill" style="width: 0%"></div>
                </div>
            `;

            progressList.appendChild(progressItem);

            // Upload file
            try {
                await this.uploadSingleFile(file, operationId, (progress) => {
                    const percentage = Math.round((progress.loaded / progress.total) * 100);
                    progressItem.querySelector('.progress-percentage').textContent = `${percentage}%`;
                    progressItem.querySelector('.progress-fill').style.width = `${percentage}%`;
                    progressItem.querySelector('.progress-status').textContent =
                        percentage === 100 ? 'Complete' : `Uploading... ${percentage}%`;
                });

                // Mark as complete
                progressItem.classList.add('progress-complete');

            } catch (error) {
                console.error(`❌ Upload failed for ${file.name}:`, error);
                progressItem.classList.add('progress-error');
                progressItem.querySelector('.progress-status').textContent = `Failed: ${error.message}`;
            }
        }

        this.showToast(`${files.length} files uploaded`, 'success');

        // Hide progress after delay
        setTimeout(() => {
            progressContainer.style.display = 'none';
        }, 2000);
    }

    async uploadSingleFile(file, operationId, progressCallback) {
        const formData = new FormData();
        formData.append('file', file);
        formData.append('agent_id', this.fileManagerState.currentAgent);
        formData.append('operation_id', operationId);

        const xhr = new XMLHttpRequest();
        xhr.open('POST', `${this.apiBase}/files/upload`);

        xhr.upload.addEventListener('progress', (e) => {
            if (e.lengthComputable && e.total) {
                progressCallback({
                    loaded: e.loaded,
                    total: e.total
                });
            }
        });

        return new Promise((resolve, reject) => {
            xhr.onload = () => {
                if (xhr.status === 200) {
                    resolve(JSON.parse(xhr.responseText));
                } else {
                    reject(new Error(`Upload failed: ${xhr.status}`));
                }
            };

            xhr.onerror = () => reject(new Error('Network error'));
            xhr.send(formData);
        });
    }

    searchFiles(query) {
        console.log(`🔍 Searching files: ${query}`);

        if (!this.files) return;

        const searchLower = query.toLowerCase();
        const filteredFiles = this.files.filter(file =>
            file.name.toLowerCase().includes(searchLower) ||
            file.path.toLowerCase().includes(searchLower) ||
            file.mime_type.toLowerCase().includes(searchLower)
        );

        this.renderFilteredFileList(filteredFiles);

        const resultCount = filteredFiles.length;
        this.showToast(`Found ${resultCount} files matching "${query}"`, 'info');
    }

    clearFileSearch() {
        document.getElementById('file-search').value = '';
        this.renderFilteredFileList(this.files);
        this.showToast('Search cleared', 'info');
    }

    renderFilteredFileList(filteredFiles) {
        const tbody = document.getElementById('file-manager-tbody');
        if (!tbody) return;

        if (filteredFiles.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="empty-hint">No files found</td></tr>';
            return;
        }

        tbody.innerHTML = filteredFiles.map(file => `
            <tr>
                <td>
                    <input type="checkbox" class="file-checkbox" data-file-path="${this.escapeHtml(file.path)}" 
                           onchange="dashboard.updateFileSelection(this)">
                    ${file.is_directory ? '' : `
                        <span class="file-icon">${this.getFileIcon(file.mime_type)}</span>
                        ${this.escapeHtml(file.name)}
                    `}
                </td>
                <td>${this.escapeHtml(file.mime_type || '-')}</td>
                <td>${this.escapeHtml(file.size_human || '-')}</td>
                <td>${this.formatRelativeTime(file.modified_at)}</td>
                <td>
                    ${file.is_directory ? `
                        <button class="btn btn-sm btn-info" onclick="dashboard.enterDirectory('${this.escapeHtml(file.path)}')">
                            📁 Enter
                        </button>
                    ` : `
                        <button class="btn btn-sm btn-info" onclick="dashboard.previewFile('${this.escapeHtml(file.path)}')">
                            👁️ Preview
                        </button>
                        <button class="btn btn-sm btn-secondary" onclick="dashboard.downloadFile('${this.escapeHtml(file.path)}')">
                            ⬇️ Download
                        </button>
                        <button class="btn btn-sm btn-warning" onclick="dashboard.deleteFile('${this.escapeHtml(file.path)}')">
                            🗑️ Delete
                        </button>
                    `}
                </td>
            </tr>
        `).join('');

        this.updateBatchOperationButtons();
    }

    updateFileSelection(checkbox) {
        const filePath = checkbox.dataset.filePath;
        const file = this.files.find(f => f.path === filePath);

        if (file) {
            if (checkbox.checked) {
                this.fileManagerState.selectedFiles.add(file);
            } else {
                this.fileManagerState.selectedFiles.delete(file);
            }
        }

        this.updateSelectedCount();
        this.updateBatchOperationButtons();
    }

    updateSelectedCount() {
        const countElement = document.getElementById('selected-count');
        const count = this.fileManagerState.selectedFiles.size;

        if (countElement) {
            countElement.textContent = `${count} files selected`;
        }
    }

    updateBatchOperationButtons() {
        const hasSelection = this.fileManagerState.selectedFiles.size > 0;

        const buttons = ['delete-selected', 'download-selected', 'copy-selected', 'move-selected'];
        buttons.forEach(buttonId => {
            const button = document.getElementById(buttonId);
            if (button) {
                button.disabled = !hasSelection;
            }
        });
    }

    toggleSelectAll() {
        const headerCheckbox = document.getElementById('header-checkbox');
        const fileCheckboxes = document.querySelectorAll('.file-checkbox');
        const isChecked = headerCheckbox.checked;

        fileCheckboxes.forEach(checkbox => {
            checkbox.checked = isChecked;
            this.updateFileSelection(checkbox);
        });

        this.updateSelectedCount();
    }

    async deleteSelectedFiles() {
        if (this.fileManagerState.selectedFiles.size === 0) {
            this.showToast('No files selected', 'warning');
            return;
        }

        const confirmed = confirm(`Delete ${this.fileManagerState.selectedFiles.size} selected files?`);
        if (!confirmed) return;

        const filesToDelete = Array.from(this.fileManagerState.selectedFiles);

        for (const file of filesToDelete) {
            try {
                await this.deleteFile(file.path);
            } catch (error) {
                console.error(`❌ Failed to delete ${file.name}:`, error);
            }
        }

        this.fileManagerState.selectedFiles.clear();
        this.updateSelectedCount();
        this.refreshFileManager();
    }

    async downloadSelectedFiles() {
        if (this.fileManagerState.selectedFiles.size === 0) {
            this.showToast('No files selected', 'warning');
            return;
        }

        const filesToDownload = Array.from(this.fileManagerState.selectedFiles);

        for (const file of filesToDownload) {
            try {
                await this.downloadFile(file.path);
            } catch (error) {
                console.error(`❌ Failed to download ${file.name}:`, error);
            }
        }
    }

    async copySelectedFiles() {
        if (this.fileManagerState.selectedFiles.size === 0) {
            this.showToast('No files selected', 'warning');
            return;
        }

        // Implementation would depend on backend support for file copying
        this.showToast(`Copying ${this.fileManagerState.selectedFiles.size} files...`, 'info');
    }

    async moveSelectedFiles() {
        if (this.fileManagerState.selectedFiles.size === 0) {
            this.showToast('No files selected', 'warning');
            return;
        }

        // Implementation would depend on backend support for file moving
        this.showToast(`Moving ${this.fileManagerState.selectedFiles.size} files...`, 'info');
    }

    enterDirectory(path) {
        this.fileManagerState.currentPath = path;
        this.loadAgentFiles(this.fileManagerState.currentAgent, path);
    }

    async previewFile(filePath) {
        const file = this.files.find(f => f.path === filePath);
        if (!file || file.is_directory) {
            this.showToast('Cannot preview directory or file not found', 'warning');
            return;
        }

        const previewContainer = document.getElementById('file-preview-container');
        const previewContent = document.getElementById('file-preview-content');

        previewContainer.style.display = 'block';

        // Determine preview type based on MIME type
        if (file.mime_type.startsWith('text/')) {
            // Text file preview
            try {
                const response = await fetch(`${this.apiBase}/files/download?agent_id=${this.fileManagerState.currentAgent}&file_path=${encodeURIComponent(filePath)}`);
                const content = await response.text();
                previewContent.innerHTML = `<pre style="background: #1a1a1a; color: #00ff00; padding: 1rem; border-radius: 4px; overflow: auto;">${this.escapeHtml(content)}</pre>`;
            } catch (error) {
                previewContent.innerHTML = `<div class="error-message">Failed to load file: ${error.message}</div>`;
            }
        } else if (file.mime_type.startsWith('image/')) {
            // Image preview
            previewContent.innerHTML = `<img src="${this.apiBase}/files/download?agent_id=${this.fileManagerState.currentAgent}&file_path=${encodeURIComponent(filePath)}" style="max-width: 100%; height: auto;" alt="${this.escapeHtml(file.name)}">`;
        } else {
            // Generic file info
            previewContent.innerHTML = `
                <div class="file-info">
                    <p><strong>Name:</strong> ${this.escapeHtml(file.name)}</p>
                    <p><strong>Type:</strong> ${this.escapeHtml(file.mime_type)}</p>
                    <p><strong>Size:</strong> ${this.escapeHtml(file.size_human || '-')}</p>
                    <p><strong>Modified:</strong> ${this.formatRelativeTime(file.modified_at)}</p>
                    <p><em>Preview not available for this file type</em></p>
                </div>
            `;
        }
    }

    closeFilePreview() {
        const previewContainer = document.getElementById('file-preview-container');
        if (previewContainer) {
            previewContainer.style.display = 'none';
        }
    }

    setFileManagerView(viewType) {
        this.fileManagerState.currentView = viewType;

        // Update button states
        const buttons = {
            'list': document.getElementById('list-view-btn'),
            'grid': document.getElementById('grid-view-btn'),
            'tree': document.getElementById('tree-view-btn')
        };

        Object.keys(buttons).forEach(key => {
            if (buttons[key]) {
                buttons[key].classList.toggle('active', key === viewType);
            }
        });

        // Update rendering
        this.renderFilteredFileList(this.files);

        console.log(`📋 File manager view changed to: ${viewType}`);
    }

    setupFileKeyboardShortcuts() {
        document.addEventListener('keydown', (e) => {
            // Ctrl+A: Select all
            if (e.ctrlKey && e.key === 'a') {
                e.preventDefault();
                this.toggleSelectAll();
            }

            // Delete key: Delete selected files
            if (e.key === 'Delete') {
                e.preventDefault();
                this.deleteSelectedFiles();
            }

            // Escape: Close modal
            if (e.key === 'Escape') {
                const modal = document.getElementById('file-manager-modal');
                if (modal) {
                    modal.remove();
                }
            }
        });
    }

    setupFileContextMenu() {
        const fileList = document.getElementById('file-manager-tbody');
        if (!fileList) return;

        fileList.addEventListener('contextmenu', (e) => {
            e.preventDefault();

            const row = e.target.closest('tr');
            if (!row) return;

            const filePath = row.querySelector('.file-checkbox')?.dataset.filePath;
            const file = this.files.find(f => f.path === filePath);

            if (file) {
                this.showFileContextMenu(e.clientX, e.clientY, file);
            }
        });

        // Hide context menu on click
        document.addEventListener('click', () => {
            this.hideFileContextMenu();
        });
    }

    showFileContextMenu(x, y, file) {
        // Remove existing context menu
        this.hideFileContextMenu();

        const menu = document.createElement('div');
        menu.className = 'context-menu';
        menu.style.left = `${x}px`;
        menu.style.top = `${y}px`;
        menu.innerHTML = `
            <div class="context-menu-item" onclick="dashboard.previewFile('${this.escapeHtml(file.path)}')">
                👁️ Preview
            </div>
            <div class="context-menu-item" onclick="dashboard.downloadFile('${this.escapeHtml(file.path)}')">
                ⬇️ Download
            </div>
            <div class="context-menu-item" onclick="dashboard.deleteFile('${this.escapeHtml(file.path)}')">
                🗑️ Delete
            </div>
            <div class="context-menu-separator"></div>
            <div class="context-menu-item" onclick="dashboard.copyFilePath('${this.escapeHtml(file.path)}')">
                📋 Copy Path
            </div>
        `;

        document.body.appendChild(menu);

        // Position menu within viewport
        const rect = menu.getBoundingClientRect();
        if (rect.right > window.innerWidth) {
            menu.style.left = `${window.innerWidth - rect.width}px`;
        }
        if (rect.bottom > window.innerHeight) {
            menu.style.top = `${window.innerHeight - rect.height}px`;
        }
    }

    hideFileContextMenu() {
        const menu = document.querySelector('.context-menu');
        if (menu) {
            menu.remove();
        }
    }

    copyFilePath(filePath) {
        if (navigator.clipboard) {
            navigator.clipboard.writeText(filePath);
            this.showToast('File path copied to clipboard', 'success');
        }
    }

    async loadAgentFiles(agentId) {
        try {
            const response = await fetch(`${this.apiBase}/files/list?agent_id=${encodeURIComponent(agentId)}`, {
                headers: this.getHeaders()
            });

            if (!response.ok) {
                throw new Error(`Failed to load files: ${response.status}`);
            }

            const data = await response.json();
            this.files = data.files || [];
            
            // Update the file list display
            const tbody = document.getElementById('file-manager-tbody');
            if (tbody) {
                tbody.innerHTML = this.renderAdvancedFileList();
            }
            
        } catch (error) {
            console.error('Error loading agent files:', error);
            this.files = [];
            this.showToast(`Failed to load files: ${error.message}`, 'error');
        }
    }

    renderAdvancedFileList() {
        if (this.files.length === 0) {
            return '<tr><td colspan="7" class="empty-hint">No files found</td></tr>';
        }

        return this.files.map(file => `
        <tr>
            <td><input type="checkbox" class="file-select" data-path="${this.escapeHtml(file.path)}"></td>
            <td>
                <span class="file-icon">${file.is_directory ? '📁' : this.getFileIcon(file.mime_type)}</span>
                ${this.escapeHtml(file.name)}
            </td>
            <td>${this.escapeHtml(file.mime_type || '-')}</td>
            <td>${this.escapeHtml(file.size_human || '-')}</td>
            <td>${this.formatRelativeTime(file.modified_at)}</td>
            <td>${this.escapeHtml(file.permissions || '-')}</td>
            <td>
                ${!file.is_directory ? `
                    <button class="btn btn-sm btn-info" onclick="dashboard.downloadFile('${this.escapeHtml(file.path)}')">
                        ⬇️ Download
                    </button>
                ` : ''}
            </td>
        </tr>
        `).join('');
    }

    getFileIcon(mimeType) {
        if (!mimeType) return '📄';
        if (mimeType.startsWith('image/')) return '🖼️';
        if (mimeType.startsWith('video/')) return '🎥';
        if (mimeType.startsWith('audio/')) return '🎵';
        if (mimeType.includes('pdf')) return '📕';
        if (mimeType.includes('zip') || mimeType.includes('compressed')) return '📦';
        if (mimeType.includes('text/')) return '📝';
        return '📄';
    }

    async switchFileManagerAgent(agentId) {
        this.currentAgent = agentId;
        await this.loadAgentFiles(agentId);

        const tbody = document.getElementById('file-manager-tbody');
        if (tbody) {
            tbody.innerHTML = this.renderAdvancedFileList();
        }
    }

    async refreshFileList() {
        if (!this.currentAgent) return;
        await this.loadAgentFiles(this.currentAgent);

        const tbody = document.getElementById('file-manager-tbody');
        if (tbody) {
            tbody.innerHTML = this.renderAdvancedFileList();
        }

        this.showToast('File list refreshed', 'success');
    }

    async uploadFileToAgent() {
        const input = document.createElement('input');
        input.type = 'file';
        input.onchange = async (e) => {
            const file = e.target.files[0];
            if (!file) return;

            const formData = new FormData();
            formData.append('file', file);

            try {
                const response = await fetch(
                    `${this.apiBase}/files/upload?agent_id=${this.currentAgent}`,
                    {
                        method: 'POST',
                        headers: {
                            'Authorization': `Bearer ${this.token}`
                        },
                        body: formData
                    }
                );

                const result = await response.json();

                if (!response.ok) {
                    throw new Error(result.error || 'Upload failed');
                }

                this.showToast(`File "${file.name}" uploaded successfully`, 'success');
                await this.refreshFileList();

            } catch (error) {
                console.error('File upload error:', error);
                this.showToast(`Upload failed: ${error.message}`, 'error');
            }
        };
        input.click();
    }

    async downloadFile(filePath) {
        const url = `${this.apiBase}/files/download?agent_id=${this.currentAgent}&path=${encodeURIComponent(filePath)}&token=${this.token}`;
        window.open(url, '_blank');
    }

    // ==================== NEW: CERTIFICATE VIEWER ====================

    async loadCertificates() {
        try {
            const response = await fetch(`${this.apiBase}/certificates`, {
                headers: this.getHeaders()
            });

            if (!response.ok) {
                throw new Error(`Failed to load certificates: ${response.status}`);
            }

            const data = await response.json();
            this.certificates = data.certificates || [];
            
        } catch (error) {
            console.error('Error loading certificates:', error);
            this.certificates = [];
            this.showToast(`Failed to load certificates: ${error.message}`, 'error');
        }
    }

    async openCertificateViewer() {
        await this.loadCertificates();

        const modal = document.createElement('div');
        modal.className = 'modal';
        modal.id = 'cert-viewer-modal';
        modal.innerHTML = `
        <div class="modal-content" style="max-width: 1000px;">
        <div class="modal-header">
        <h3>🔐 PKI Certificate Inspector</h3>
        <button class="modal-close" onclick="this.closest('.modal').remove()">&times;</button>
        </div>
        <div class="modal-body">
        <table class="data-table">
        <thead>
        <tr>
        <th>Type</th>
        <th>ID/Subject</th>
        <th>Serial Number</th>
        <th>Valid From</th>
        <th>Valid Until</th>
        <th>Status</th>
        <th>Actions</th>
        </tr>
        </thead>
        <tbody>
        ${this.renderCertificateList()}
        </tbody>
        </table>
        </div>
        </div>
        `;

        document.body.appendChild(modal);
        
        // Show the modal - THIS WAS MISSING!
        modal.classList.add('active');
        modal.style.display = 'flex';
        
        modal.addEventListener('click', (e) => {
            if (e.target === modal) modal.remove();
        });
    }

    renderCertificateList() {
        if (this.certificates.length === 0) {
            return '<tr><td colspan="7" class="empty-hint">No certificates found</td></tr>';
        }

        return this.certificates.map(cert => `
        <tr>
        <td><span class="type-badge">${this.escapeHtml(cert.type)}</span></td>
        <td><code>${this.truncate(cert.subject, 40)}</code></td>
        <td><code>${this.truncate(cert.serial_number, 16)}</code></td>
        <td>${this.formatTimestamp(cert.not_before)}</td>
        <td>${this.formatTimestamp(cert.not_after)}</td>
        <td>
        <span class="status-badge status-${cert.is_valid ? 'success' : 'error'}">
        ${cert.is_valid ? 'Valid' : 'Expired'}
        </span>
        </td>
        <td>
        <button class="btn btn-sm btn-info" onclick="dashboard.viewCertificateDetails('${cert.type}', '${cert.agent_id || cert.operator_id || 'ca_root'}')">
        Details
        </button>
        </td>
        </tr>
        `).join('');
    }

    async viewCertificateDetails(certType, certId) {
        try {
            const response = await fetch(
                `${this.apiBase}/certificates/${certType}/${certId}`,
                { headers: this.getHeaders() }
            );

            if (!response.ok) throw new Error('Failed to fetch certificate details');

            const data = await response.json();
            const cert = data.certificate;

            const detailModal = document.createElement('div');
            detailModal.className = 'modal';
            detailModal.innerHTML = `
            <div class="modal-content" style="max-width: 800px;">
            <div class="modal-header">
            <h3>Certificate Details - ${this.escapeHtml(certId)}</h3>
            <button class="modal-close" onclick="this.closest('.modal').remove()">&times;</button>
            </div>
            <div class="modal-body">
            <div class="cert-details">
            <h4>Subject</h4>
            <pre>${JSON.stringify(cert.subject, null, 2)}</pre>

            <h4>Issuer</h4>
            <pre>${JSON.stringify(cert.issuer, null, 2)}</pre>

            <h4>Validity</h4>
            <div class="detail-table">
            <div class="detail-row">
            <span>Not Before:</span>
            <code>${this.formatTimestamp(cert.not_before)}</code>
            </div>
            <div class="detail-row">
            <span>Not After:</span>
            <code>${this.formatTimestamp(cert.not_after)}</code>
            </div>
            <div class="detail-row">
            <span>Status:</span>
            <span class="status-badge status-${cert.is_valid ? 'success' : 'error'}">
            ${cert.is_valid ? 'Valid' : 'Expired'}
            </span>
            </div>
            </div>

            <h4>Public Key</h4>
            <pre>${JSON.stringify(cert.public_key, null, 2)}</pre>

            <h4>Fingerprint (SHA-256)</h4>
            <code class="fingerprint">${cert.fingerprint_sha256}</code>

            <h4>PEM Certificate</h4>
            <textarea readonly rows="12">${cert.pem}</textarea>
            </div>
            </div>
            </div>
            `;

            document.body.appendChild(detailModal);
            detailModal.addEventListener('click', (e) => {
                if (e.target === detailModal) detailModal.remove();
            });

        } catch (error) {
            console.error('Certificate details error:', error);
            this.showToast(`Failed to load certificate: ${error.message}`, 'error');
        }
    }

    // ==================== HEALTH FUNCTIONS ====================

    async loadHealth() {
        const container = document.getElementById('health-content');
        if (!container) return;

        try {
            // Show loading state
            container.innerHTML = `
                <div style="text-align: center; padding: 2rem;">
                    <div style="font-size: 4rem;">🏥</div>
                    <p style="color: var(--text-secondary);">Loading system health information...</p>
                </div>
            `;

            // Fetch health from API
            const response = await fetch(`${this.apiBase}/health/detailed`, {
                headers: this.getHeaders()
            });

            if (!response.ok) {
                // Fallback to basic health endpoint
                const basicResponse = await fetch(`${this.apiBase}/state`, {
                    headers: this.getHeaders()
                });
                if (!basicResponse.ok) throw new Error('Failed to fetch health');
                const state = await basicResponse.json();
                this.renderHealthContent(container, state);
                return;
            }

            const health = await response.json();
            this.renderHealthContent(container, health);

        } catch (error) {
            console.error('Error loading health:', error);
            container.innerHTML = `
                <div style="text-align: center; padding: 2rem;">
                    <div style="font-size: 4rem;">⚠️</div>
                    <p style="color: var(--text-secondary);">Failed to load health information</p>
                    <p style="color: var(--error); font-size: 0.9rem;">${this.escapeHtml(error.message)}</p>
                </div>
            `;
        }
    }

    async refreshHealth() {
        await this.loadHealth();
        this.showToast('Health information refreshed', 'success');
    }

    renderHealthContent(container, data) {
        // Handle Health API response format
        // data.components = { pki: {...}, database: {...}, sessions: {...}, security: {...} }
        const componentsData = data.components || {};
        
        // Map API components to display cards
        const componentMap = [
            { 
                name: 'PKI', 
                status: componentsData.pki?.status || 'unknown',
                message: componentsData.pki?.message || '',
                icon: '🔐'
            },
            { 
                name: 'Database', 
                status: componentsData.database?.status || 'unknown',
                message: componentsData.database?.message || '',
                icon: '🗄️',
                count: componentsData.database?.details?.agent_count
            },
            { 
                name: 'Sessions', 
                status: componentsData.sessions?.status || 'unknown',
                message: componentsData.sessions?.message || '',
                icon: '🔒',
                count: componentsData.sessions?.details?.active_sessions
            },
            { 
                name: 'Security', 
                status: componentsData.security?.status || 'unknown',
                message: componentsData.security?.message || '',
                icon: '🛡️'
            },
        ];

        const getStatusColor = (status) => {
            switch (status) {
                case 'healthy': return 'var(--success)';
                case 'ok': return 'var(--success)';
                case 'degraded': return 'var(--warning)';
                case 'unhealthy': return 'var(--error)';
                case 'unknown': return 'var(--text-secondary)';
                default: return 'var(--text-secondary)';
            }
        };

        const getStatusText = (status) => {
            switch (status) {
                case 'healthy': return '✅ Healthy';
                case 'ok': return '✅ OK';
                case 'degraded': return '⚠️ Degraded';
                case 'unhealthy': return '❌ Unhealthy';
                case 'unknown': return '❓ Unknown';
                default: return status || 'Unknown';
            }
        };

        container.innerHTML = `
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1rem; margin-bottom: 2rem;">
                ${componentMap.map(comp => `
                    <div style="
                        background: var(--bg-secondary);
                        border-radius: var(--radius-md);
                        padding: 1.5rem;
                        text-align: center;
                        border: 2px solid ${getStatusColor(comp.status)};
                    ">
                        <div style="font-size: 2rem; margin-bottom: 0.5rem;">${comp.icon}</div>
                        <h4 style="margin-bottom: 0.5rem;">${comp.name}</h4>
                        <div style="
                            background: ${getStatusColor(comp.status)}20;
                            color: ${getStatusColor(comp.status)};
                            padding: 0.5rem 1rem;
                            border-radius: var(--radius-sm);
                            font-weight: 600;
                            display: inline-block;
                            margin-bottom: 0.5rem;
                        ">
                            ${getStatusText(comp.status)}${comp.count !== undefined ? ` (${comp.count})` : ''}
                        </div>
                        ${comp.message ? `<p style="font-size: 0.85rem; color: var(--text-secondary); margin-top: 0.5rem;">${comp.message}</p>` : ''}
                    </div>
                `).join('')}
            </div>
            
            <div style="padding: 1.5rem; background: var(--bg-secondary); border-radius: var(--radius-md);">
                <h4 style="margin-bottom: 1rem;">📊 System Overview</h4>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem;">
                    <div>
                        <strong>Overall Status:</strong> 
                        <span style="color: ${getStatusColor(data.status)};">${getStatusText(data.status)}</span>
                    </div>
                    <div>
                        <strong>Last Check:</strong> ${data.timestamp ? this.formatRelativeTime(data.timestamp) : 'Just now'}
                    </div>
                    <div>
                        <strong>Uptime:</strong> ${this.formatUptime(data.uptime_seconds || 0)}
                    </div>
                </div>
            </div>
        `;
    }

    // ==================== METRICS FUNCTIONS ====================

    async loadMetricsUI(category = '') {
        const container = document.getElementById('metrics-content');
        if (!container) return;

        try {
            // Show loading state
            container.innerHTML = `
                <div style="text-align: center; padding: 2rem;">
                    <div style="font-size: 4rem;">📊</div>
                    <p style="color: var(--text-secondary);">Loading system metrics...</p>
                </div>
            `;

            // Fetch metrics from API
            const response = await fetch(`${this.apiBase}/stats`, {
                headers: this.getHeaders()
            });

            if (!response.ok) throw new Error('Failed to fetch metrics');

            const metrics = await response.json();
            this.renderMetricsContent(container, metrics, category);

        } catch (error) {
            console.error('Error loading metrics:', error);
            container.innerHTML = `
                <div style="text-align: center; padding: 2rem;">
                    <div style="font-size: 4rem;">⚠️</div>
                    <p style="color: var(--text-secondary);">Failed to load metrics</p>
                    <p style="color: var(--error); font-size: 0.9rem;">${this.escapeHtml(error.message)}</p>
                </div>
            `;
        }
    }

    renderMetricsContent(container, metrics, category) {
        // Default metrics display
        const metricCards = [
            { label: 'Total Agents', value: metrics.total_agents || 0, icon: '🤖' },
            { label: 'Active Agents', value: metrics.active_agents || 0, icon: '✅' },
            { label: 'Total Commands', value: metrics.total_commands || 0, icon: '⚡' },
            { label: 'Pending Commands', value: metrics.pending_commands || 0, icon: '⏳' },
            { label: 'Successful', value: metrics.successful_commands || 0, icon: '✓' },
            { label: 'Failed', value: metrics.failed_commands || 0, icon: '❌' },
            { label: 'Success Rate', value: `${this.calculateSuccessRate()}%`, icon: '📈' },
            { label: 'Uptime', value: this.formatUptime(metrics.uptime_seconds || 0), icon: '⏱️' },
        ];

        // Filter by category if specified
        let filteredCards = metricCards;
        if (category === 'operations') {
            filteredCards = metricCards.slice(0, 4);
        } else if (category === 'errors') {
            filteredCards = metricCards.slice(4, 7);
        } else if (category === 'performance') {
            filteredCards = metricCards.slice(6);
        }

        container.innerHTML = `
            <div class="metrics-grid">
                ${filteredCards.map(card => `
                    <div class="metric-card">
                        <h4>${card.icon} ${card.label}</h4>
                        <div class="metric-value">${card.value}</div>
                    </div>
                `).join('')}
            </div>
        `;
    }

    // ==================== NEW: ADVANCED UI FEATURES ====================

    // Toggle audit search panel
    toggleAuditSearch() {
        const panel = document.getElementById('audit-search-panel');
        if (panel) {
            panel.style.display = panel.style.display === 'none' ? 'block' : 'none';
        }
    }

    // Open audit search panel
    openAuditSearch() {
        const panel = document.getElementById('audit-search-panel');
        if (panel) {
            panel.style.display = 'block';
        }
    }

    // Execute audit search
    async executeAuditSearch() {
        const startTime = document.getElementById('audit-start-time').value;
        const endTime = document.getElementById('audit-end-time').value;
        const eventType = document.getElementById('audit-event-type').value;
        const operator = document.getElementById('audit-operator').value;

        const filters = {};
        if (startTime) filters.start_time = startTime;
        if (endTime) filters.end_time = endTime;
        if (eventType) filters.event_type = eventType;
        if (operator) filters.operator = operator;

        this.showToast('Searching audit logs...', 'info');
        const logs = await this.loadAuditLogs(filters);
        this.displayAuditLogs(logs);
    }

    // Clear audit search
    clearAuditSearch() {
        document.getElementById('audit-start-time').value = '';
        document.getElementById('audit-end-time').value = '';
        document.getElementById('audit-event-type').value = '';
        document.getElementById('audit-operator').value = '';
        this.refreshAuditLogs();
    }

    // Refresh audit logs
    async refreshAuditLogs() {
        this.showToast('Refreshing audit logs...', 'info');
        const logs = await this.loadAuditLogs();
        this.displayAuditLogs(logs);
    }

    // Display audit logs in table
    displayAuditLogs(logs) {
        const tbody = document.getElementById('audit-tbody');
        if (!tbody) return;

        if (logs.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="5" class="empty-hint">
                        <div style="text-align: center; padding: 2rem;">
                            <div style="font-size: 3rem;">📝</div>
                            <div>No audit entries found</div>
                        </div>
                    </td>
                </tr>
            `;
            return;
        }

        tbody.innerHTML = logs.map(log => `
            <tr>
                <td>${this.formatTimestamp(log.timestamp)}</td>
                <td><span class="type-badge">${this.escapeHtml(log.event_type)}</span></td>
                <td>${this.escapeHtml(log.operator || 'System')}</td>
                <td>${this.escapeHtml(log.details || '')}</td>
                <td>
                    <button class="btn btn-sm btn-secondary" onclick="dashboard.viewAuditDetails('${log.id}')">
                        Details
                    </button>
                </td>
            </tr>
        `).join('');
    }

    // Export audit logs
    async exportAuditLogs() {
        try {
            const logs = await this.loadAuditLogs();
            const csv = this.convertToCSV(logs);
            const blob = new Blob([csv], { type: 'text/csv' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `audit_logs_${new Date().toISOString().split('T')[0]}.csv`;
            a.click();
            URL.revokeObjectURL(url);
            this.showToast('Audit logs exported successfully', 'success');
        } catch (error) {
            this.showToast('Failed to export audit logs', 'error');
        }
    }

    // Convert data to CSV
    convertToCSV(data) {
        if (!data || data.length === 0) return '';

        const headers = Object.keys(data[0]);
        const csvRows = [headers.join(',')];

        for (const row of data) {
            const values = headers.map(header => {
                const value = row[header] || '';
                return `"${String(value).replace(/"/g, '""')}"`;
            });
            csvRows.push(values.join(','));
        }

        return csvRows.join('\n');
    }

    // Refresh health monitoring
    async refreshHealth() {
        this.showToast('Loading health information...', 'info');
        const health = await this.loadDetailedHealth();
        this.displayHealth(health);
    }

    // Display health information
    displayHealth(health) {
        const content = document.getElementById('health-content');
        if (!content) return;

        if (!health) {
            content.innerHTML = `
                <div style="text-align: center; padding: 2rem;">
                    <div style="font-size: 3rem;">❌</div>
                    <p style="color: var(--text-secondary);">Failed to load health information</p>
                </div>
            `;
            return;
        }

        content.innerHTML = `
            <div class="health-grid">
                <div class="health-card">
                    <h4>🔗 Connection Status</h4>
                    <div class="health-indicator ${health.connected ? 'healthy' : 'unhealthy'}">
                        ${health.connected ? '✅ Connected' : '❌ Disconnected'}
                    </div>
                </div>
                <div class="health-card">
                    <h4>🤖 Agents</h4>
                    <div class="health-indicator ${health.agents?.healthy ? 'healthy' : 'warning'}">
                        ${health.agents?.count || 0} agents (${health.agents?.active || 0} active)
                    </div>
                </div>
                <div class="health-card">
                    <h4>💾 Database</h4>
                    <div class="health-indicator ${health.database?.healthy ? 'healthy' : 'unhealthy'}">
                        ${health.database?.status || 'Unknown'}
                    </div>
                </div>
                <div class="health-card">
                    <h4>🔐 PKI</h4>
                    <div class="health-indicator ${health.pki?.healthy ? 'healthy' : 'unhealthy'}">
                        ${health.pki?.status || 'Unknown'}
                    </div>
                </div>
                <div class="health-card">
                    <h4>⏰ Uptime</h4>
                    <div class="health-indicator healthy">
                        ${health.uptime || 'Unknown'}
                    </div>
                </div>
                <div class="health-card">
                    <h4>📊 Memory Usage</h4>
                    <div class="health-indicator ${health.memory?.usage > 80 ? 'warning' : 'healthy'}">
                        ${health.memory?.usage || 'N/A'}%
                    </div>
                </div>
            </div>
        `;
    }

    // Load and display metrics
    async loadMetricsUI(category = null) {
        const container = document.getElementById('metrics-content');
        if (!container) return;

        try {
            // Fetch metrics from API
            const response = await fetch(`${this.apiBase}/stats`, {
                headers: this.getHeaders()
            });

            if (!response.ok) throw new Error('Failed to fetch metrics');

            const metrics = await response.json();
            this.renderMetricsContent(container, metrics, category);

        } catch (error) {
            console.error('Error loading metrics:', error);
            container.innerHTML = `
                <div style="text-align: center; padding: 2rem;">
                    <div style="font-size: 4rem;">⚠️</div>
                    <p style="color: var(--text-secondary);">Failed to load metrics</p>
                    <p style="color: var(--error); font-size: 0.9rem;">${this.escapeHtml(error.message)}</p>
                </div>
            `;
        }
    }

    // Refresh metrics (single definition)
    async refreshMetrics() {
        const category = document.getElementById('metrics-category')?.value || '';
        this.showToast('Refreshing metrics...', 'info');
        await this.loadMetricsUI(category);
        this.showToast('Metrics refreshed', 'success');
    }

    // Display metrics
    displayMetrics(metrics) {
        const content = document.getElementById('metrics-content');
        if (!content) return;

        if (!metrics) {
            content.innerHTML = `
                <div style="text-align: center; padding: 2rem;">
                    <div style="font-size: 3rem;">❌</div>
                    <p style="color: var(--text-secondary);">Failed to load metrics</p>
                </div>
            `;
            return;
        }

        const metricsHtml = Object.entries(metrics).map(([key, value]) => `
            <div class="metric-card">
                <h4>${this.formatMetricName(key)}</h4>
                <div class="metric-value">${this.formatMetricValue(value)}</div>
            </div>
        `).join('');

        content.innerHTML = `
            <div class="metrics-grid">
                ${metricsHtml}
            </div>
        `;
    }

    // Format metric name for display
    formatMetricName(name) {
        return name.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
    }

    // Format metric value for display
    formatMetricValue(value) {
        if (typeof value === 'number') {
            if (value > 1000000) return `${(value / 1000000).toFixed(1)}M`;
            if (value > 1000) return `${(value / 1000).toFixed(1)}K`;
            return value.toFixed(1);
        }
        return String(value);
    }

    // ==================== NEW: ADVANCED FEATURES ====================

    // Load audit logs with advanced filtering
    async loadAuditLogs(filters = {}) {
        try {
            const params = new URLSearchParams();
            if (filters.start_time) params.append('start_time', filters.start_time);
            if (filters.end_time) params.append('end_time', filters.end_time);
            if (filters.event_type) params.append('event_type', filters.event_type);
            if (filters.operator) params.append('operator', filters.operator);
            if (filters.limit) params.append('limit', filters.limit);

            const response = await fetch(`${this.apiBase}/audit/logs?${params}`, {
                headers: this.getHeaders()
            });

            if (!response.ok) throw new Error('Failed to fetch audit logs');

            const data = await response.json();
            return data.logs || [];
        } catch (error) {
            console.error('Failed to load audit logs:', error);
            this.showToast(`Failed to load audit logs: ${error.message}`, 'error');
            return [];
        }
    }

    // Search audit logs with advanced query
    async searchAuditLogs(query) {
        try {
            const response = await fetch(`${this.apiBase}/audit/search`, {
                method: 'POST',
                headers: this.getHeaders(),
                body: JSON.stringify(query)
            });

            if (!response.ok) throw new Error('Failed to search audit logs');

            const data = await response.json();
            return data.results || [];
        } catch (error) {
            console.error('Failed to search audit logs:', error);
            this.showToast(`Failed to search audit logs: ${error.message}`, 'error');
            return [];
        }
    }

    // Load detailed health information
    async loadDetailedHealth() {
        try {
            const response = await fetch(`${this.apiBase}/health/detailed`, {
                headers: this.getHeaders()
            });

            if (!response.ok) throw new Error('Failed to fetch health details');

            const data = await response.json();
            return data;
        } catch (error) {
            console.error('Failed to load health details:', error);
            this.showToast(`Failed to load health details: ${error.message}`, 'error');
            return null;
        }
    }

    // Load system metrics
    async loadMetrics(category = null) {
        try {
            let url = `${this.apiBase}/metrics`;
            if (category) {
                url = `${this.apiBase}/metrics/${category}`;
            }

            const response = await fetch(url, {
                headers: this.getHeaders()
            });

            if (!response.ok) throw new Error('Failed to fetch metrics');

            const data = await response.json();
            return data;
        } catch (error) {
            console.error('Failed to load metrics:', error);
            this.showToast(`Failed to load metrics: ${error.message}`, 'error');
            return null;
        }
    }

    // Load command configuration
    async loadCommandConfig() {
        try {
            const response = await fetch(`${this.apiBase}/config/commands`, {
                headers: this.getHeaders()
            });

            if (!response.ok) throw new Error('Failed to fetch command config');

            const data = await response.json();
            return data.commands || [];
        } catch (error) {
            console.error('Failed to load command config:', error);
            this.showToast(`Failed to load command config: ${error.message}`, 'error');
            return [];
        }
    }

    // Load audit events (different from logs)
    async loadAuditEvents() {
        try {
            const response = await fetch(`${this.apiBase}/audit/events`, {
                headers: this.getHeaders()
            });

            if (!response.ok) throw new Error('Failed to fetch audit events');

            const data = await response.json();
            return data.events || [];
        } catch (error) {
            console.error('Failed to load audit events:', error);
            this.showToast(`Failed to load audit events: ${error.message}`, 'error');
            return [];
        }
    }

    // ==================== AGENT DETAILS ====================

    async viewAgentDetails(agentId) {
        try {
            const response = await fetch(`${this.apiBase}/agents/${agentId}`, {
                headers: this.getHeaders()
            });

            if (!response.ok) throw new Error('Failed to fetch agent details');

            const details = await response.json();

            const modal = document.createElement('div');
            modal.className = 'modal';
            modal.innerHTML = `
            <div class="modal-content">
            <div class="modal-header">
            <h3>Agent Details - ${this.escapeHtml(agentId)}</h3>
            <button class="modal-close" onclick="this.closest('.modal').remove()">&times;</button>
            </div>
            <div class="modal-body">
            <div class="agent-details">
            <div class="detail-section">
            <h4>Information</h4>
            <table class="detail-table">
            <tr><td>Agent ID</td><td><code>${this.escapeHtml(details.agent.agent_id)}</code></td></tr>
            <tr><td>IP Address</td><td>${this.escapeHtml(details.agent.ip_address)}</td></tr>
            <tr><td>Status</td><td><span class="status-badge status-${details.agent.status}">${this.escapeHtml(details.agent.status)}</span></td></tr>
            <tr><td>Connected</td><td>${this.formatTimestamp(details.agent.connected_at)}</td></tr>
            <tr><td>Last Seen</td><td>${this.formatRelativeTime(details.agent.last_seen)}</td></tr>
            <tr><td>Certificate</td><td>${this.escapeHtml(details.agent.certificate_subject)}</td></tr>
            </table>
            </div>
            <div class="detail-section">
            <h4>Recent Commands</h4>
            ${details.commands.length > 0 ? `
                <table class="data-table">
                <thead>
                <tr><th>Type</th><th>Status</th><th>Time</th><th>Payload</th></tr>
                </thead>
                <tbody>
                ${details.commands.slice(0, 5).map(cmd => `
                    <tr>
                    <td><span class="type-badge">${this.escapeHtml(cmd.command_type)}</span></td>
                    <td><span class="status-badge status-${cmd.status}">${this.escapeHtml(cmd.status)}</span></td>
                    <td>${this.formatRelativeTime(cmd.created_at)}</td>
                    <td>${this.truncate(cmd.payload, 30)}</td>
                    </tr>
                    `).join('')}
                    </tbody>
                    </table>
                    ` : '<p class="empty-hint">No commands issued</p>'}
                    </div>
                    </div>
                    </div>
                    <div class="modal-footer">
                    <button class="btn btn-primary" onclick="dashboard.sendCommandTo('${this.escapeHtml(agentId)}'); this.closest('.modal').remove();">Send Command</button>
                    <button class="btn btn-secondary" onclick="this.closest('.modal').remove()">Close</button>
                    </div>
                    </div>
                    `;

            document.body.appendChild(modal);
            
            // Show the modal - THIS WAS MISSING!
            modal.classList.add('active');
            modal.style.display = 'flex';
            
            modal.addEventListener('click', (e) => {
                if (e.target === modal) modal.remove();
            });

        } catch (error) {
            console.error('Agent details error:', error);
            this.showToast(`Failed to load agent details: ${error.message}`, 'error');
        }
    }

    async disconnectAgent(agentId) {
        if (!confirm(`Are you sure you want to disconnect agent ${agentId}?`)) {
            return;
        }

        this.sendCommandTo(agentId);
        setTimeout(() => {
            const typeSelect = document.getElementById('cmd-type');
            if (typeSelect) typeSelect.value = 'exit';
            this.handleCommandTypeChange('exit');
        }, 100);
    }

    // ==================== AUTO REFRESH ====================

    startAutoRefresh() {
        this.stopAutoRefresh();

        if (this.autoRefresh) {
            this.refreshTimer = setInterval(() => {
                this.loadData();
            }, this.refreshInterval);
        }
    }

    stopAutoRefresh() {
        if (this.refreshTimer) {
            clearInterval(this.refreshTimer);
            this.refreshTimer = null;
        }
    }

    // ==================== UI UPDATES ====================

    updateConnectionStatus(status) {
        const indicator = document.querySelector('.status-indicator');
        const text = document.querySelector('.status-text');

        if (indicator && text) {
            indicator.className = `status-indicator ${status}`;
            text.textContent = status === 'connected' ? 'Connected' :
                status === 'loading' ? 'Loading...' :
                    status === 'error' ? 'Error' : 'Disconnected';
        }
    }

    updateLastRefresh() {
        const el = document.getElementById('last-refresh');
        if (el) {
            el.textContent = new Date().toLocaleTimeString();
        }
    }

    // ==================== TOAST NOTIFICATIONS ====================

    showToast(message, type = 'info', duration = 5000) {
        const container = document.getElementById('toast-container');
        if (!container) return;

        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;

        const icons = {
            success: '✅',
            error: '❌',
            warning: '⚠️',
            info: 'ℹ️'
        };

        toast.innerHTML = `
        <span class="toast-icon">${icons[type] || 'ℹ️'}</span>
        <span class="toast-message">${this.escapeHtml(message)}</span>
        <button class="toast-close" onclick="this.parentElement.remove()">&times;</button>
        `;

        container.appendChild(toast);

        requestAnimationFrame(() => {
            toast.classList.add('show');
        });

        setTimeout(() => {
            toast.classList.remove('show');
            setTimeout(() => toast.remove(), 300);
        }, duration);
    }

    // ==================== UTILITIES ====================

    escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    truncate(text, maxLength) {
        if (!text) return '-';
        if (text.length <= maxLength) return text;
        return text.substring(0, maxLength - 3) + '...';
    }

    formatTimestamp(timestamp) {
        if (!timestamp) return '-';
        try {
            const date = new Date(timestamp);
            return date.toLocaleString();
        } catch {
            return timestamp;
        }
    }

    formatRelativeTime(timestamp) {
        if (!timestamp) return '-';
        try {
            const date = new Date(timestamp);
            const now = new Date();
            const diff = Math.floor((now - date) / 1000);

            if (diff < 60) return 'just now';
            if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
            if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
            return `${Math.floor(diff / 86400)}d ago`;
        } catch {
            return timestamp;
        }
    }

    formatUptime(seconds) {
        const days = Math.floor(seconds / 86400);
        const hours = Math.floor((seconds % 86400) / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);

        if (days > 0) return `${days}d ${hours}h`;
        if (hours > 0) return `${hours}h ${minutes}m`;
        return `${minutes}m`;
    }

    calculateSuccessRate() {
        const total = this.stats.successful_commands + this.stats.failed_commands;
        if (total === 0) return '100%';
        return `${Math.round((this.stats.successful_commands / total) * 100)}%`;
    }

    // ==================== EXPORT ====================

    exportData(format = 'json') {
        const data = {
            stats: this.stats,
            agents: this.agents,
            commands: this.commands,
            exported_at: new Date().toISOString()
        };

        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `securecomm-export-${new Date().toISOString().split('T')[0]}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        this.showToast('Data exported successfully', 'success');
    }
}

// Initialize dashboard when DOM is ready with robust retry mechanism
document.addEventListener('DOMContentLoaded', () => {
    console.log('🚀 DOM Content Loaded - Initializing SecureComm Dashboard...');

    // Robust initialization with retry mechanism
    const initializeDashboard = (retryCount = 0) => {
        try {
            console.log(`🔍 Attempting initialization (attempt ${retryCount + 1})...`);

            // Verify critical DOM elements exist
            const criticalButtons = [
                'btn-new-command',
                'btn-payload-builder',
                'btn-file-manager',
                'btn-cert-viewer',
                'btn-batch-command'
            ];

            const missingButtons = criticalButtons.filter(id => !document.getElementById(id));

            if (missingButtons.length > 0 && retryCount < 10) {
                console.log(`⚠️ Missing buttons: ${missingButtons.join(', ')}`);
                console.log(`🔄 Retrying in ${100 * (retryCount + 1)}ms...`);

                setTimeout(() => initializeDashboard(retryCount + 1), 100 * (retryCount + 1));
                return;
            }

            if (missingButtons.length > 0) {
                console.error('❌ Critical buttons not found after 10 attempts:', missingButtons);
                console.log('🔧 Available buttons:');
                criticalButtons.forEach(id => {
                    const element = document.getElementById(id);
                    console.log(`  ${id}: ${element ? '✅ FOUND' : '❌ MISSING'}`);
                });
                return;
            }

            // All critical elements found, proceed with initialization
            console.log('✅ All critical elements found, initializing dashboard...');
            window.dashboard = new SecureCommDashboard();
            console.log('✅ SecureComm Dashboard initialized successfully!');
            console.log('🔍 Dashboard object:', window.dashboard);

            // Test button binding
            setTimeout(() => {
                console.log('🧪 Testing button bindings...');
                const testButtons = ['btn-new-command', 'btn-payload-builder', 'btn-file-manager', 'btn-cert-viewer'];
                testButtons.forEach(id => {
                    const btn = document.getElementById(id);
                    if (btn && btn.onclick) {
                        console.log(`✅ ${id}: Event listener bound`);
                    } else {
                        console.log(`❌ ${id}: Event listener NOT bound`);
                    }
                });
            }, 1000);

        } catch (error) {
            console.error('❌ Failed to initialize dashboard:', error);
            if (retryCount < 3) {
                console.log(`🔄 Retrying initialization in ${1000 * (retryCount + 1)}ms...`);
                setTimeout(() => initializeDashboard(retryCount + 1), 1000 * (retryCount + 1));
            } else {
                console.error('❌ Initialization failed after 3 attempts');
                // Show user-friendly error message
                const errorDiv = document.createElement('div');
                errorDiv.innerHTML = `
                    <div style="position: fixed; top: 20px; right: 20px; background: #ff4444; color: white; padding: 1rem; border-radius: 8px; z-index: 9999;">
                        <h4>⚠️ Dashboard Initialization Failed</h4>
                        <p>Please refresh the page or contact support.</p>
                        <button onclick="location.reload()" style="background: white; color: #ff4444; border: none; padding: 0.5rem 1rem; border-radius: 4px; cursor: pointer;">Refresh</button>
                    </div>
                `;
                document.body.appendChild(errorDiv);
            }
        }
    };

    // Start initialization
    initializeDashboard();
});

// Export for testing
if (typeof module !== 'undefined' && module.exports) {
    module.exports = SecureCommDashboard;
}
