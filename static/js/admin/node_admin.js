/**
 * node_admin.js - Handles dynamic behavior for the Node admin form
 * 
 * Shows or hides lighthouse configuration based on checkbox state
 */
(function($) {
    $(document).ready(function() {
        // Function to toggle the lighthouse configuration fieldset
        function toggleLighthouseFieldset() {
            var isLighthouse = $('#id_is_lighthouse').is(':checked');
            var lighthouseFieldset = $('.lighthouse-config').closest('fieldset');
            
            if (isLighthouse) {
                lighthouseFieldset.show();
            } else {
                lighthouseFieldset.hide();
            }
        }
        
        // Run on page load
        toggleLighthouseFieldset();
        
        // Run when checkbox changes
        $('#id_is_lighthouse').change(function() {
            toggleLighthouseFieldset();
        });
    });
})(django.jQuery); 