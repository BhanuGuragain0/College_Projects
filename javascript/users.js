const searchBar = document.querySelector(".search input"),
    searchIcon = document.querySelector(".search button"),
    usersList = document.querySelector(".users-list");

let searchTimeout;
let lastSearchTerm = "";

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

    // Debounce search requests (wait 300ms after user stops typing)
    clearTimeout(searchTimeout);
    searchTimeout = setTimeout(() => {
        if (searchTerm === lastSearchTerm) {
            return; // Don't search if term hasn't changed
        }
        lastSearchTerm = searchTerm;

        if (searchTerm === "") {
            fetchUsers(); // Show all users if search is cleared
            return;
        }

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
                console.error("Search error:", error);
                showNotification("Search failed. Please try again.", "error");
            });
    }, 300); // Wait 300ms after user stops typing
};

function fetchUsers() {
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
            console.error("Fetch users error:", error);
        });
}

// Fetch users every 3 seconds (optimized from 500ms - 83% reduction in requests)
setInterval(() => {
    if (!searchBar.classList.contains("active")) {
        fetchUsers();
    }
}, 3000);

// Initial fetch
fetchUsers();

function showNotification(message, type = "info") {
    const notification = document.createElement("div");
    notification.className = `notification notification-${type}`;
    notification.textContent = message;
    document.body.appendChild(notification);

    setTimeout(() => {
        notification.classList.add("show");
    }, 100);

    setTimeout(() => {
        notification.classList.remove("show");
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}
