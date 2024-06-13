<script nonce="{{ g.nonce }}">
if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('/static/firebase-messaging-sw.js')
  .then(function(registration) {
    console.log('Service Worker registration successful with scope: ', registration.scope);
  }).catch(function(err) {
    console.log('Service Worker registration failed: ', err);
  });
}
</script>

<script nonce="{{ g.nonce }}">
    document.addEventListener("DOMContentLoaded", function() {
        // Scroll to decrypted messages if they exist
        {% if decrypted_messages %}
            document.getElementById('decrypted-messages').scrollIntoView();
        {% endif %}

        // Show the notification dropdown
        function showNotification(message, isError = false) {
            var notification = document.createElement('div');
            notification.className = 'notification-dropdown' + (isError ? ' error' : '');
            notification.textContent = message;
            document.body.appendChild(notification);

            // Display the notification
            notification.style.display = 'block';

            // Hide the notification after 5 seconds
            setTimeout(function() {
                notification.style.display = 'none';
                document.body.removeChild(notification);
            }, 5000);
        }

        // Look for flash messages inserted by Flask and show them as notifications
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    var isError = "{{ category }}" === "error"; // Determine if the message is an error based on its category
                    showNotification("{{ message }}", isError);
                {% endfor %}
            {% endif %}
        {% endwith %}

        // File input handling
        document.getElementById('image-button').addEventListener('click', function() {
            document.getElementById('image').click();
        });

        document.getElementById('image').addEventListener('change', function(event) {
            var fileName = event.target.files[0] ? event.target.files[0].name : 'No file chosen';
            document.getElementById('file-name').textContent = fileName;

            // Show the loading spinner
            document.getElementById('loading-spinner').style.display = 'inline-block';
        });

        // Hide the loading spinner after form submission
        document.getElementById('message-form').addEventListener('submit', function() {
            document.getElementById('loading-spinner').style.display = 'none';
        });
    });
</script>
