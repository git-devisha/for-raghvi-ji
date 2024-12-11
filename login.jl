// Form loading animation
const form = [...document.querySelector('.login-container').children];

form.forEach((item, i) => {
    setTimeout(() => {
        item.style.opacity = 1;
    }, i * 100);
});

// On window load, redirect if session storage contains user data
window.onload = () => {
    if (sessionStorage.username) {
        location.href = '/'; // Redirect to home if logged in
    }
};

// Form validation
const usernameInput = document.querySelector('input[name="username"]');
const passwordInput = document.querySelector('input[name="password"]');
const loginButton = document.querySelector('button[type="submit"]');

loginButton.addEventListener('click', (e) => {
    e.preventDefault(); // Prevent form submission

    const username = usernameInput.value.trim();
    const password = passwordInput.value.trim();

    if (!username || !password) {
        displayAlert('Both fields are required');
        return;
    }

    // Simulate an API call for login
    fetch('/login-user', {
        method: 'POST',
        headers: new Headers({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({
            username: username,
            password: password
        })
    })
        .then((response) => response.json())
        .then((data) => {
            validateLogin(data);
        })
        .catch((error) => {
            console.error('Error during login:', error);
            displayAlert('Something went wrong. Please try again later.');
        });
});

// Validate login response
const validateLogin = (data) => {
    if (data.success) {
        sessionStorage.username = data.username; // Save user data to session storage
        location.href = '/'; // Redirect to home page
    } else {
        displayAlert(data.message || 'Invalid credentials');
    }
};

// Display alert box
const displayAlert = (message) => {
    const alertContainer = document.createElement('div');
    alertContainer.style.position = 'fixed';
    alertContainer.style.top = '10%';
    alertContainer.style.left = '50%';
    alertContainer.style.transform = 'translate(-50%, -50%)';
    alertContainer.style.backgroundColor = '#f44336';
    alertContainer.style.color = '#fff';
    alertContainer.style.padding = '10px 20px';
    alertContainer.style.borderRadius = '5px';
    alertContainer.style.boxShadow = '0 2px 10px rgba(0,0,0,0.2)';
    alertContainer.textContent = message;

    document.body.appendChild(alertContainer);

    setTimeout(() => {
        alertContainer.remove();
    }, 3000); // Remove alert after 3 seconds
};
