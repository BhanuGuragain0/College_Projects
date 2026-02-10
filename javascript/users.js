const searchBar = document.querySelector(".search input"),
    searchIcon = document.querySelector(".search button"),
    usersList = document.querySelector(".users-list");

searchIcon.onclick = () => {
    searchBar.classList.toggle("show");
    searchIcon.classList.toggle("active");
    searchBar.focus();
    if (searchBar.classList.contains("active")) {
        searchBar.value = "";
        searchBar.classList.remove("active");
    }
};

searchBar.onkeyup = () => {
    let searchTerm = searchBar.value.trim();
    if (searchTerm !== "") {
        searchBar.classList.add("active");
    } else {
        searchBar.classList.remove("active");
    }

    // Using Fetch API for better readability and modern approach
    fetch("php/search.php", {
        method: "POST",
        headers: {
            "Content-Type": "application/x-www-form-urlencoded"
        },
        body: `searchTerm=${encodeURIComponent(searchTerm)}`
    })
        .then(response => response.text())
        .then(data => {
            usersList.innerHTML = data;
        })
        .catch(error => {
            console.error("Error:", error);
        });
};

setInterval(() => {
    // Using Fetch API for better readability and modern approach
    fetch("php/users.php", {
        method: "GET"
    })
        .then(response => response.text())
        .then(data => {
            if (!searchBar.classList.contains("active")) {
                usersList.innerHTML = data;
            }
        })
        .catch(error => {
            console.error("Error:", error);
        });
}, 500);
