
const API = "/api/v1/auth";

const form = document.getElementById("authForm");
const message = document.getElementById("message");
const submitBtn = document.getElementById("submitBtn");

let setupMode = false;

function showMessage(text) {
    message.textContent = text;
}

function setMode(isSetup) {
    setupMode = isSetup;

    document.getElementById("heading").textContent =
        isSetup ? "Create Administrator" : "Welcome Back";

    document.getElementById("subtitle").textContent =
        isSetup
            ? "Set up the first administrator account."
            : "Sign in to your Security Gateway.";

    document.getElementById("confirmField").hidden = !isSetup;

    document.getElementById("confirmPassword").required = isSetup;

    document.getElementById("password").autocomplete =
        isSetup ? "new-password" : "current-password";

    submitBtn.textContent =
        isSetup ? "Create Administrator" : "Sign In";
}

async function initializeAuth() {
    try {
        const response = await fetch(`${API}/setup-status`, {
            credentials: "same-origin"
        });

        if (!response.ok) {
            throw new Error("Could not check gateway setup.");
        }

        const data = await response.json();

        if (data.setup_required) {
            setMode(true);
        } else {
            setMode(false);
        }

    } catch (error) {
        showMessage(error.message);
    }
}

form.addEventListener("submit", async (event) => {
    event.preventDefault();

    const username =
        document.getElementById("username").value.trim();

    const password =
        document.getElementById("password").value;

    const confirmPassword =
        document.getElementById("confirmPassword").value;

    if (setupMode && password !== confirmPassword) {
        showMessage("Passwords do not match.");
        return;
    }

    submitBtn.disabled = true;
    submitBtn.textContent = "Please wait...";
    showMessage("");

    try {
        const endpoint = setupMode ? "/setup" : "/login";

        const response = await fetch(API + endpoint, {
            method: "POST",
            credentials: "same-origin",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                username,
                password
            })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "Authentication failed.");
        }

        // Session cookie is set by the Go backend.
        // Never store passwords or session tokens in localStorage.

        window.location.assign("/");

    } catch (error) {
        showMessage(error.message);
    } finally {
        submitBtn.disabled = false;
        submitBtn.textContent =
            setupMode ? "Create Administrator" : "Sign In";
    }
});

initializeAuth();
