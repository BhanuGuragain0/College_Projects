document.addEventListener('DOMContentLoaded', function() {
    const forgotPasswordForm = document.getElementById('forgotPasswordForm');
    const validationMessage = document.getElementById('validationMessage');

    forgotPasswordForm.addEventListener('submit', function(event) {
        event.preventDefault();
        const formData = new FormData(forgotPasswordForm);
        const submitBtn = forgotPasswordForm.querySelector('button[type="submit"]');
        
        submitBtn.disabled = true;
        submitBtn.textContent = 'PROCESSING...';

        fetch('php/validate-user.php', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            submitBtn.disabled = false;
            submitBtn.textContent = 'RESET PASSWORD';
            
            validationMessage.className = '';
            validationMessage.style.display = 'block';
            
            if (data.status === 'success') {
                validationMessage.classList.add('success');
                validationMessage.textContent = data.message;
                forgotPasswordForm.reset();
            } else {
                validationMessage.classList.add('error');
                validationMessage.textContent = data.message || 'An error occurred';
            }
        })
        .catch(error => {
            submitBtn.disabled = false;
            submitBtn.textContent = 'RESET PASSWORD';
            
            validationMessage.className = 'error';
            validationMessage.style.display = 'block';
            validationMessage.textContent = 'Network error. Please try again.';
            console.error('Error:', error);
        });
    });
});
