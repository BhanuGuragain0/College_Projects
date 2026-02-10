const form = document.querySelector(".login form"),
    continueBtn = form.querySelector("button"),
    errorText = form.querySelector(".error-text");

form.onsubmit = (e) => {
    e.preventDefault();
};

continueBtn.onclick = () => {
    // Using Fetch API for better readability and modern approach
    let formData = new FormData(form);

    fetch("php/login.php", {
        method: "POST",
        body: formData
    })
        .then(response => response.text())
        .then(data => {
            if (data === "success") {
                window.location.href = "users.php";
            } else {
                errorText.style.display = "block";
                errorText.textContent = data;
            }
        })
        .catch(error => {
            console.error("Error:", error);
            errorText.style.display = "block";
            errorText.textContent = "An error occurred. Please try again.";
        });
};
