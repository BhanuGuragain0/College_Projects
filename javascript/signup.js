const form = document.querySelector(".signup form"),
    continueBtn = form.querySelector(".button input"),
    errorText = form.querySelector(".error-text");

form.onsubmit = (e) => {
    e.preventDefault();
};

continueBtn.onclick = () => {
    let formData = new FormData(form);
    continueBtn.classList.add('loading');

    fetch("php/signup.php", {
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
                errorText.textContent = data.message || "Signup failed";
            }
        })
        .catch(error => {
            continueBtn.classList.remove('loading');
            console.error("Error:", error);
            errorText.style.display = "block";
            errorText.textContent = "An error occurred. Please try again.";
        });
};
