// Main JavaScript for Catalyst Networks web UI

document.addEventListener('DOMContentLoaded', function() {
    // Initialize any components that need JavaScript initialization
    
    // Show toast messages and auto-hide them after 5 seconds
    const toastMessages = document.querySelectorAll('.alert, .notification');
    toastMessages.forEach(toast => {
        setTimeout(() => {
            // Add fade-out class
            toast.classList.add('opacity-0', 'transition-opacity', 'duration-500');
            
            // After animation, remove the element
            setTimeout(() => {
                toast.remove();
            }, 500);
        }, 5000);
    });

    // Add htmx event listeners for UI feedback
    document.body.addEventListener('htmx:beforeRequest', function(event) {
        // Add loading state to buttons
        const button = event.detail.elt;
        if (button.tagName === 'BUTTON') {
            button.setAttribute('disabled', 'disabled');
            button.classList.add('opacity-75');
        }
    });

    document.body.addEventListener('htmx:afterRequest', function(event) {
        // Remove loading state from buttons
        const button = event.detail.elt;
        if (button.tagName === 'BUTTON') {
            button.removeAttribute('disabled');
            button.classList.remove('opacity-75');
        }
    });

    // Confirm dangerous actions
    document.querySelectorAll('[data-confirm]').forEach(element => {
        element.addEventListener('click', function(event) {
            const message = this.getAttribute('data-confirm');
            if (!confirm(message)) {
                event.preventDefault();
                event.stopPropagation();
                return false;
            }
        });
    });
});

// Helper function to copy text to clipboard
function copyToClipboard(text, buttonElement) {
    navigator.clipboard.writeText(text).then(() => {
        // Show copied feedback
        const originalText = buttonElement.innerHTML;
        buttonElement.innerHTML = 'Copied!';
        
        // Reset after 2 seconds
        setTimeout(() => {
            buttonElement.innerHTML = originalText;
        }, 2000);
    }).catch(err => {
        console.error('Failed to copy text: ', err);
    });
} 