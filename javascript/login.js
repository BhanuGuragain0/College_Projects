const form = document.querySelector(".login form"),
    continueBtn = form.querySelector("button"),
    errorText = form.querySelector(".error-text");

form.onsubmit = (e) => {
    e.preventDefault();
};

continueBtn.onclick = () => {
    let formData = new FormData(form);
    continueBtn.classList.add('loading');

    fetch("php/login.php", {
        method: "POST",
        body: formData
    })
        .then(response => response.json())
        .then(data => {
            continueBtn.classList.remove('loading');
            if (data.status === "success") {
                window.location.href = "users.php";
            } else {
                errorText.style.display = "block";
                errorText.textContent = data.message || "Login failed";
            }
        })
        .catch(error => {
            continueBtn.classList.remove('loading');
            console.error("Error:", error);
            errorText.style.display = "block";
            errorText.textContent = "An error occurred. Please try again.";
        });
};
