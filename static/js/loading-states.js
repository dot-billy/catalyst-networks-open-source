/**
 * Loading States and Feedback JavaScript
 * Handles loading states, toast notifications, and user feedback
 */

class LoadingStates {
    constructor() {
        this.toastContainer = null;
        this.init();
    }

    init() {
        this.createToastContainer();
        this.setupFormLoading();
        this.setupButtonLoading();
    }

    /**
     * Create toast container if it doesn't exist
     */
    createToastContainer() {
        if (!document.getElementById('toast-container')) {
            this.toastContainer = document.createElement('div');
            this.toastContainer.id = 'toast-container';
            this.toastContainer.className = 'fixed top-4 right-4 z-50 space-y-2';
            document.body.appendChild(this.toastContainer);
        } else {
            this.toastContainer = document.getElementById('toast-container');
        }
    }

    /**
     * Show loading spinner
     */
    showSpinner(element, options = {}) {
        const {
            size = 'md',
            color = 'primary',
            text = '',
            centered = true
        } = options;

        const spinner = document.createElement('div');
        spinner.className = `loading-spinner ${centered ? 'flex flex-col items-center justify-center' : ''}`;
        spinner.innerHTML = `
            <div class="relative">
                <div class="animate-spin rounded-full border-2 border-catalyst-gray-600 ${this.getSizeClass(size)}"></div>
                <div class="animate-spin rounded-full border-2 border-t-2 border-t-${color === 'primary' ? 'catalyst-teal' : color} ${this.getSizeClass(size)} absolute top-0 left-0"></div>
            </div>
            ${text ? `<p class="mt-3 text-sm text-catalyst-gray-400 animate-pulse">${text}</p>` : ''}
        `;

        element.appendChild(spinner);
        return spinner;
    }

    /**
     * Hide loading spinner
     */
    hideSpinner(spinner) {
        if (spinner && spinner.parentNode) {
            spinner.parentNode.removeChild(spinner);
        }
    }

    /**
     * Show skeleton loader
     */
    showSkeleton(element, type = 'card', options = {}) {
        const { lines = 3 } = options;
        
        const skeleton = document.createElement('div');
        skeleton.className = 'skeleton-loader';
        skeleton.innerHTML = this.getSkeletonHTML(type, lines);
        
        element.appendChild(skeleton);
        return skeleton;
    }

    /**
     * Hide skeleton loader
     */
    hideSkeleton(skeleton) {
        if (skeleton && skeleton.parentNode) {
            skeleton.parentNode.removeChild(skeleton);
        }
    }

    /**
     * Show progress bar
     */
    showProgress(element, value, options = {}) {
        const {
            max = 100,
            size = 'md',
            color = 'primary',
            showLabel = true,
            animated = true
        } = options;

        const percentage = Math.round((value / max) * 100);
        
        const progress = document.createElement('div');
        progress.className = 'progress-bar';
        progress.innerHTML = `
            ${showLabel ? `
                <div class="flex justify-between items-center mb-2">
                    <span class="text-sm font-medium text-catalyst-gray-300">Progress</span>
                    <span class="text-sm text-catalyst-gray-400">${percentage}%</span>
                </div>
            ` : ''}
            <div class="w-full bg-catalyst-gray-700 rounded-full overflow-hidden">
                <div class="progress-fill ${this.getSizeClass(size)} bg-${color === 'primary' ? 'catalyst-teal' : color} rounded-full transition-all duration-500 ease-out ${animated ? 'animate-pulse' : ''}" 
                     style="width: ${percentage}%"
                     role="progressbar" 
                     aria-valuenow="${value}" 
                     aria-valuemin="0" 
                     aria-valuemax="${max}"
                     aria-label="Progress: ${percentage}%">
                </div>
            </div>
        `;
        
        element.appendChild(progress);
        return progress;
    }

    /**
     * Show toast notification
     */
    showToast(type, message, options = {}) {
        const {
            title = '',
            duration = 5000,
            dismissible = true,
            position = 'top-right'
        } = options;

        const toast = document.createElement('div');
        toast.className = `toast toast-${position} fixed z-50`;
        toast.innerHTML = `
            <div class="toast-content bg-catalyst-gray-800 border border-catalyst-gray-700 rounded-lg shadow-lg p-4 max-w-sm w-full">
                <div class="flex items-start">
                    <div class="flex-shrink-0 mr-3">
                        ${this.getToastIcon(type)}
                    </div>
                    <div class="flex-1">
                        ${title ? `<h4 class="text-sm font-semibold text-catalyst-gray-100 mb-1">${title}</h4>` : ''}
                        <p class="text-sm text-catalyst-gray-300">${message}</p>
                    </div>
                    ${dismissible ? `
                        <div class="flex-shrink-0 ml-3">
                            <button class="inline-flex text-catalyst-gray-400 hover:text-catalyst-gray-300 focus:outline-none focus:text-catalyst-gray-300 transition-colors duration-200" onclick="this.parentElement.parentElement.parentElement.remove()">
                                <svg class="w-4 h-4" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
                                </svg>
                            </button>
                        </div>
                    ` : ''}
                </div>
            </div>
        `;

        this.toastContainer.appendChild(toast);

        // Auto-dismiss
        if (duration > 0) {
            setTimeout(() => {
                if (toast.parentNode) {
                    toast.remove();
                }
            }, duration);
        }

        return toast;
    }

    /**
     * Setup form loading states
     */
    setupFormLoading() {
        document.addEventListener('submit', (e) => {
            const form = e.target;
            if (form.classList.contains('form-loading')) {
                return;
            }

            // Add loading class
            form.classList.add('form-loading');
            
            // Show loading spinner
            const spinner = this.showSpinner(form, {
                text: 'Processing...',
                centered: true
            });

            // Remove loading state after form submission
            setTimeout(() => {
                form.classList.remove('form-loading');
                this.hideSpinner(spinner);
            }, 2000);
        });
    }

    /**
     * Setup button loading states
     */
    setupButtonLoading() {
        document.addEventListener('click', (e) => {
            const button = e.target.closest('button[data-loading]');
            if (!button) return;

            const loadingText = button.dataset.loadingText || 'Loading...';
            const originalText = button.textContent;
            
            // Show loading state
            button.disabled = true;
            button.classList.add('btn-loading');
            button.innerHTML = `
                <svg class="animate-spin -ml-1 mr-2 h-4 w-4 text-current" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                    <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                    <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
                ${loadingText}
            `;

            // Simulate loading (replace with actual async operation)
            setTimeout(() => {
                button.disabled = false;
                button.classList.remove('btn-loading');
                button.textContent = originalText;
            }, 2000);
        });
    }

    /**
     * Get size class for components
     */
    getSizeClass(size) {
        const sizes = {
            sm: 'w-4 h-4',
            md: 'w-6 h-6',
            lg: 'w-8 h-8',
            xl: 'w-12 h-12'
        };
        return sizes[size] || sizes.md;
    }

    /**
     * Get skeleton HTML based on type
     */
    getSkeletonHTML(type, lines) {
        switch (type) {
            case 'card':
                return `
                    <div class="card animate-pulse">
                        <div class="flex items-center space-x-4 mb-4">
                            <div class="w-12 h-12 bg-catalyst-gray-700 rounded-full"></div>
                            <div class="flex-1 space-y-2">
                                <div class="h-4 bg-catalyst-gray-700 rounded w-3/4"></div>
                                <div class="h-3 bg-catalyst-gray-700 rounded w-1/2"></div>
                            </div>
                        </div>
                        <div class="space-y-3">
                            <div class="h-3 bg-catalyst-gray-700 rounded"></div>
                            <div class="h-3 bg-catalyst-gray-700 rounded w-5/6"></div>
                            <div class="h-3 bg-catalyst-gray-700 rounded w-4/6"></div>
                        </div>
                    </div>
                `;
            case 'table':
                return `
                    <div class="card overflow-hidden">
                        <div class="animate-pulse">
                            <div class="h-12 bg-catalyst-gray-700 mb-4"></div>
                            ${Array(5).fill(0).map(() => `
                                <div class="flex space-x-4 py-3 border-b border-catalyst-gray-700">
                                    <div class="h-4 bg-catalyst-gray-700 rounded w-1/4"></div>
                                    <div class="h-4 bg-catalyst-gray-700 rounded w-1/6"></div>
                                    <div class="h-4 bg-catalyst-gray-700 rounded w-1/6"></div>
                                    <div class="h-4 bg-catalyst-gray-700 rounded w-1/6"></div>
                                    <div class="h-4 bg-catalyst-gray-700 rounded w-1/6"></div>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                `;
            case 'list':
                return `
                    <div class="space-y-4">
                        ${Array(5).fill(0).map(() => `
                            <div class="flex items-center space-x-4 p-4 bg-catalyst-gray-800 rounded-lg animate-pulse">
                                <div class="w-10 h-10 bg-catalyst-gray-700 rounded-full"></div>
                                <div class="flex-1 space-y-2">
                                    <div class="h-4 bg-catalyst-gray-700 rounded w-1/3"></div>
                                    <div class="h-3 bg-catalyst-gray-700 rounded w-1/2"></div>
                                </div>
                                <div class="w-20 h-8 bg-catalyst-gray-700 rounded"></div>
                            </div>
                        `).join('')}
                    </div>
                `;
            case 'text':
                return `
                    <div class="space-y-3 animate-pulse">
                        ${Array(lines).fill(0).map((_, i) => `
                            <div class="h-4 bg-catalyst-gray-700 rounded ${i === lines - 1 ? 'w-3/4' : 'w-full'}"></div>
                        `).join('')}
                    </div>
                `;
            case 'button':
                return '<div class="h-10 bg-catalyst-gray-700 rounded animate-pulse w-32"></div>';
            default:
                return '<div class="h-4 bg-catalyst-gray-700 rounded animate-pulse"></div>';
        }
    }

    /**
     * Get toast icon based on type
     */
    getToastIcon(type) {
        const icons = {
            success: '<svg class="w-5 h-5 text-catalyst-success" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" /></svg>',
            error: '<svg class="w-5 h-5 text-catalyst-error" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>',
            warning: '<svg class="w-5 h-5 text-catalyst-warning" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z" /></svg>',
            info: '<svg class="w-5 h-5 text-catalyst-teal" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>'
        };
        return icons[type] || icons.info;
    }
}

// Initialize loading states when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.loadingStates = new LoadingStates();
});

// Export for use in other scripts
window.LoadingStates = LoadingStates;
