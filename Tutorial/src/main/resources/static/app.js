const API = "http://localhost:8080";

function register() {
    fetch(`${API}/auth/register`, {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
            username: regUser.value,
            password: regPass.value,
            role: regRole.value
        })
    }).then(r => r.text()).then(alert);
}

function login() {
    fetch(`${API}/auth/login`, {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
            username: loginUser.value,
            password: loginPass.value
        })
    })
    .then(res => res.json())
    .then(data => {
        localStorage.setItem("accessToken", data.accessToken);
        localStorage.setItem("refreshToken", data.refreshToken);
        window.location = "dashboard.html";
    })
    .catch(() => alert("Login failed"));
}

function getPublicUsers() {
    fetch(`${API}/public/users`)
        .then(r => r.json())
        .then(data => output.textContent = JSON.stringify(data, null, 2));
}

function getAdminUsers() {
    fetch(`${API}/admin/users`, {
        headers: {
            "Authorization": "Bearer " + localStorage.getItem("accessToken")
        }
    })
    .then(r => r.json())
    .then(data => output.textContent = JSON.stringify(data, null, 2));
}

function refreshToken() {
    fetch(`${API}/auth/refresh`, {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
            refreshToken: localStorage.getItem("refreshToken")
        })
    })
    .then(r => r.json())
    .then(data => {
        localStorage.setItem("accessToken", data.accessToken);
        alert("Token refreshed");
    });
}

function logout() {
    localStorage.clear();
    window.location = "index.html";
}
