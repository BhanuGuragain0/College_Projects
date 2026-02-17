const searchBar = document.querySelector(".search input"),
    usersList = document.querySelector(".users-list"),
    searchBtn = document.querySelector(".search button");

// Toggle search input
searchBtn.onclick = () => {
    searchBar.classList.toggle("show");
    searchBtn.classList.toggle("active");
    searchBar.focus();
    if (searchBar.classList.contains("show")) {
        searchBar.value = "";
    }
};

// Search users
searchBar.onkeyup = () => {
    let searchTerm = searchBar.value.trim();
    if (searchTerm !== "") {
        searchBar.classList.add("active");
    } else {
        searchBar.classList.remove("active");
    }

    fetch(`php/search.php?search=${encodeURIComponent(searchTerm)}`)
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                renderUsers(data.users);
            } else {
                usersList.innerHTML = `<div class="text">${data.message || 'No users found'}</div>`;
            }
        })
        .catch(error => {
            console.error("Search error:", error);
        });
};

// Fetch users list
function fetchUsers() {
    fetch("php/users.php")
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                renderUsers(data.users);
            } else {
                usersList.innerHTML = `<div class="text">${data.message || 'No users available'}</div>`;
            }
        })
        .catch(error => {
            console.error("Fetch users error:", error);
            usersList.innerHTML = '<div class="text">Error loading users</div>';
        });
}

// Render users list
function renderUsers(users) {
    if (!users || users.length === 0) {
        usersList.innerHTML = '<div class="text">No users available to chat</div>';
        return;
    }

    let html = '';
    users.forEach(user => {
        const statusClass = user.status === 'Active now' ? '' : 'offline';
        const statusText = user.status === 'Active now' ? 'online' : 'offline';
        
        html += `<a href="chat.php?user_id=${user.unique_id}">
                    <div class="content">
                        <img src="php/images/${user.img}" alt="${user.fname}">
                        <div class="details">
                            <span>${user.fname} ${user.lname}</span>
                            <p>${user.status || 'Click to start chatting'}</p>
                        </div>
                    </div>
                    <div class="status-dot ${statusClass}" title="${statusText}">
                        <i class="fas fa-circle"></i>
                    </div>
                </a>`;
    });
    
    usersList.innerHTML = html;
}

// Refresh users periodically
setInterval(() => {
    if (!searchBar.classList.contains("active")) {
        fetchUsers();
    }
}, 5000);

// Initial load
document.addEventListener('DOMContentLoaded', fetchUsers);
