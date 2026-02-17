/**
 * SecureComm Dashboard - Advanced State Management
 * Centralized state with subscriber pattern and history tracking
 *
 * Features:
 * - Centralized application state
 * - Reactive updates via subscribers
 * - History tracking for debugging
 * - Immutability guarantees
 * - Performance optimizations
 *
 * Author: SecureComm Team
 * Version: 1.0.0
 */

class DashboardState {
    constructor() {
        // Application state
        this.state = {
            agents: [],
            commands: [],
            audit: [],
            stats: {},
            selectedAgent: null,
            ui: {
                currentPage: 'dashboard',
                connectionStatus: 'disconnected',
                lastRefresh: null,
                isLoading: false,
                sidebarOpen: true,
                theme: localStorage.getItem('theme') || 'dark'
            }
        };

        // Subscriber management
        this.subscribers = new Map();
        this.history = [];
        this.historyLimit = 100;
        this.maxHistorySize = 1000;  // Events to keep
    }

    /**
     * Subscribe to state changes
     *
     * Returns unsubscribe function for cleanup
     *
     * Example:
     *   const unsubscribe = state.subscribe('agents', (agents) => {
     *       console.log('Agents changed:', agents);
     *   });
     *   unsubscribe();  // Stop listening
     */
    subscribe(key, callback) {
        if (!this.subscribers.has(key)) {
            this.subscribers.set(key, []);
        }

        this.subscribers.get(key).push(callback);

        // Return unsubscribe function
        return () => {
            const callbacks = this.subscribers.get(key);
            const index = callbacks.indexOf(callback);
            if (index > -1) {
                callbacks.splice(index, 1);
            }
        };
    }

    /**
     * Update state at specified path
     *
     * Uses dot notation for nested access:
     *   state.setState('ui.currentPage', 'agents')
     *   state.setState('agents', newAgents)
     *
     * Automatically notifies subscribers and records history
     */
    setState(path, value) {
        // Check if value actually changed (prevent unnecessary updates)
        const oldValue = this.getState(path);
        if (this.deepEqual(oldValue, value)) {
            return;  // No change
        }

        // Update state using nested path
        const keys = path.split('.');
        let obj = this.state;

        for (let i = 0; i < keys.length - 1; i++) {
            const key = keys[i];
            if (!(key in obj)) {
                obj[key] = {};
            }
            obj = obj[key];
        }

        const lastKey = keys[keys.length - 1];
        obj[lastKey] = value;

        // Record in history for debugging
        this.recordHistory({
            timestamp: Date.now(),
                           path,
                           oldValue: this.deepClone(oldValue),
                           newValue: this.deepClone(value)
        });

        // Notify subscribers
        this.notifySubscribers(path, value);
    }

    /**
     * Get state at specified path
     *
     * Returns undefined if path doesn't exist
     */
    getState(path) {
        const keys = path.split('.');
        return keys.reduce((obj, key) => obj?.[key], this.state);
    }

    /**
     * Get entire state (immutable copy)
     */
    getFullState() {
        return this.deepClone(this.state);
    }

    /**
     * Batch multiple state updates
     *
     * Only notifies subscribers once after all updates
     */
    batchUpdate(updates) {
        const changes = [];

        // Temporarily disable notifications
        const originalNotify = this.notifySubscribers.bind(this);
        this.notifySubscribers = () => { };  // No-op

        // Apply updates
        for (const [path, value] of Object.entries(updates)) {
            const oldValue = this.getState(path);
            if (!this.deepEqual(oldValue, value)) {
                // Apply update manually
                const keys = path.split('.');
                let obj = this.state;
                for (let i = 0; i < keys.length - 1; i++) {
                    obj = obj[keys[i]];
                }
                obj[keys[keys.length - 1]] = value;

                changes.push({
                    path,
                    oldValue: this.deepClone(oldValue),
                             newValue: this.deepClone(value)
                });
            }
        }

        // Re-enable notifications
        this.notifySubscribers = originalNotify;

        // Record history once
        this.recordHistory({
            timestamp: Date.now(),
                           type: 'batch',
                           changes
        });

        // Notify each changed path
        for (const change of changes) {
            originalNotify.call(this, change.path, change.newValue);
        }
    }

    /**
     * Notify all subscribers for a path
     */
    notifySubscribers(key, value) {
        const callbacks = this.subscribers.get(key) || [];

        for (const callback of callbacks) {
            try {
                callback(value);
            } catch (error) {
                console.error(`Subscriber error for ${key}:`, error);
            }
        }
    }

    /**
     * Record state change in history
     *
     * Keeps last N changes for debugging
     */
    recordHistory(event) {
        this.history.push({
            ...event,
            id: this.history.length + 1
        });

        // Trim history if too large
        if (this.history.length > this.maxHistorySize) {
            this.history = this.history.slice(-this.maxHistorySize);
        }
    }

    /**
     * Get history of state changes
     *
     * Useful for debugging and auditing
     */
    getHistory(limit = 50) {
        return this.history.slice(-limit);
    }

    /**
     * Clear history
     */
    clearHistory() {
        this.history = [];
    }

    /**
     * Deep equality check
     */
    deepEqual(a, b) {
        if (a === b) return true;
        if (a == null || b == null) return false;
        if (typeof a !== 'object' || typeof b !== 'object') return false;

        const keysA = Object.keys(a);
        const keysB = Object.keys(b);

        if (keysA.length !== keysB.length) return false;

        return keysA.every(key => this.deepEqual(a[key], b[key]));
    }

    /**
     * Deep clone object
     */
    deepClone(obj) {
        if (obj === null || typeof obj !== 'object') return obj;
        if (obj instanceof Date) return new Date(obj);
        if (obj instanceof Array) return obj.map(item => this.deepClone(item));
        if (obj instanceof Object) {
            const cloned = {};
            for (const key in obj) {
                if (obj.hasOwnProperty(key)) {
                    cloned[key] = this.deepClone(obj[key]);
                }
            }
            return cloned;
        }
    }

    /**
     * Export state for persistence
     */
    export() {
        return {
            state: this.deepClone(this.state),
            history: this.history.slice(-this.historyLimit)
        };
    }

    /**
     * Import state from export
     */
    import(data) {
        this.state = this.deepClone(data.state);
        this.history = data.history || [];
    }
}

/**
 * Advanced API Client with caching and retry logic
 */
class AdvancedAPIClient {
    constructor(baseUrl, options = {}) {
        this.baseUrl = baseUrl;
        this.cache = new Map();
        this.pendingRequests = new Map();
        this.retryConfig = {
            maxAttempts: options.maxAttempts || 3,
            initialDelay: options.initialDelay || 1000,
            maxDelay: options.maxDelay || 10000,
            backoffMultiplier: options.backoffMultiplier || 2
        };
        this.timeout = options.timeout || 10000;
        this.activeRequests = 0;
        this.maxConcurrent = options.maxConcurrent || 6;
    }

    /**
     * Fetch with caching and deduplication
     */
    async fetch(endpoint, options = {}) {
        // Check cache for GET requests
        if (options.method !== 'POST' && !options.skipCache) {
            const cached = this.getCachedResponse(endpoint);
            if (cached && !this.isCacheStale(cached)) {
                return cached.data;
            }
        }

        // Dedup in-flight requests
        if (this.pendingRequests.has(endpoint)) {
            return this.pendingRequests.get(endpoint);
        }

        const promise = this.executeWithRetry(endpoint, options);
        this.pendingRequests.set(endpoint, promise);

        try {
            const response = await promise;

            // Cache successful GET responses
            if (options.method !== 'POST') {
                this.setCachedResponse(endpoint, response);
            }

            return response;
        } finally {
            this.pendingRequests.delete(endpoint);
        }
    }

    /**
     * Execute request with retry logic
     */
    async executeWithRetry(endpoint, options, attempt = 0) {
        try {
            // Throttle concurrent requests
            while (this.activeRequests >= this.maxConcurrent) {
                await this.sleep(50);
            }

            this.activeRequests++;

            const response = await this.executeRequest(endpoint, options);
            return response;

        } catch (error) {
            const shouldRetry = attempt < this.retryConfig.maxAttempts - 1
            && this.isRetryable(error);

            if (shouldRetry) {
                const delay = this.calculateDelay(attempt);
                await this.sleep(delay);
                return this.executeWithRetry(endpoint, options, attempt + 1);
            }

            throw error;

        } finally {
            this.activeRequests--;
        }
    }

    /**
     * Execute single request
     */
    async executeRequest(endpoint, options) {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.timeout);

        try {
            const url = `${this.baseUrl}${endpoint}`;
            const response = await fetch(url, {
                ...options,
                signal: controller.signal
            });

            if (!response.ok) {
                const error = new Error(`HTTP ${response.status}`);
                error.status = response.status;
                throw error;
            }

            return await response.json();

        } finally {
            clearTimeout(timeoutId);
        }
    }

    /**
     * Check if error is retryable
     */
    isRetryable(error) {
        // Don't retry authentication errors
        if (error.status === 401 || error.status === 403) {
            return false;
        }

        // Don't retry validation errors
        if (error.status === 400) {
            return false;
        }

        // Retry network errors and server errors
        return true;
    }

    /**
     * Calculate exponential backoff delay
     */
    calculateDelay(attempt) {
        const delay = this.retryConfig.initialDelay
        * Math.pow(this.retryConfig.backoffMultiplier, attempt);

        // Add jitter to prevent thundering herd
        const jitter = delay * 0.1 * Math.random();
        const finalDelay = Math.min(
            delay + jitter,
            this.retryConfig.maxDelay
        );

        return Math.round(finalDelay);
    }

    /**
     * Get cached response
     */
    getCachedResponse(endpoint) {
        return this.cache.get(endpoint);
    }

    /**
     * Set cached response with TTL
     */
    setCachedResponse(endpoint, data, ttl = 30000) {
        this.cache.set(endpoint, {
            data,
            timestamp: Date.now(),
                       ttl
        });
    }

    /**
     * Check if cache is stale
     */
    isCacheStale(cached) {
        return Date.now() - cached.timestamp > cached.ttl;
    }

    /**
     * Clear cache
     */
    clearCache() {
        this.cache.clear();
    }

    /**
     * Sleep helper
     */
    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}

// Export for use
window.DashboardState = DashboardState;
window.AdvancedAPIClient = AdvancedAPIClient;
