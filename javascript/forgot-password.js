document.addEventListener('DOMContentLoaded', function() {
    const forgotPasswordForm = document.getElementById('forgotPasswordForm');
    const resetPasswordForm = document.getElementById('resetPasswordForm');
    const validationSection = document.getElementById('validation-section');
    const resetSection = document.getElementById('reset-section');
    const validationMessage = document.getElementById('validationMessage');
    const resetTokenInput = document.getElementById('resetToken');

    forgotPasswordForm.addEventListener('submit', function(event) {
        event.preventDefault();
        const formData = new FormData(forgotPasswordForm);

        fetch('php/validate-user.php', {
            method: 'POST',
            body: formData
        })
        .then(response => response.text())
        .then(data => {
            if (data.includes('An email with a password reset link has been sent')) {
                validationSection.style.display = 'none';
                resetSection.style.display = 'block';
                // Extract token from the response or URL if needed
            } else {
                validationMessage.textContent = data;
            }
        })
        .catch(error => console.error('Error:', error));
    });
});
