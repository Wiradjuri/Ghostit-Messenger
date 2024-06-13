// static/js/login.js
document.addEventListener('DOMContentLoaded', function() {
    const form = document.querySelector('form');
    form.addEventListener('submit', function(event) {
        // Simulate a login check
        // In a real-world scenario, you would validate this on the server side
        const username = form.querySelector('input[name="username"]').value;
        const password = form.querySelector('input[name="password"]').value;

        // Placeholder for the incorrect login check
        if (password !== 'correct_password') { // Replace 'correct_password' with your logic
            event.preventDefault(); // Prevent form submission
            flashMessage('Incorrect password. Please try again.');
        }
    });

    function flashMessage(message) {
        const alertContainer = document.createElement('div');
        alertContainer.className = 'flash-alert';
        alertContainer.innerText = message;
        document.body.appendChild(alertContainer);

        setTimeout(function() {
            alertContainer.remove();
        }, 3000); // Remove alert after 3 seconds
    }
});
