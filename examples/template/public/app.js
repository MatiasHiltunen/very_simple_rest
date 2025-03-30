// API Base URL
const API_BASE_URL = '/api';

// Store authentication token
let authToken = localStorage.getItem('token') || '';

// DOM Elements
const statusElement = document.getElementById('status');
const responsesElement = document.getElementById('responses');

// Update UI based on authentication status
function updateAuthStatus() {
    if (authToken) {
        statusElement.textContent = 'Authenticated';
        statusElement.className = 'authenticated';
        document.querySelectorAll('.requires-auth').forEach(el => {
            el.classList.remove('disabled');
        });
    } else {
        statusElement.textContent = 'Not Authenticated';
        statusElement.className = 'not-authenticated';
        document.querySelectorAll('.requires-auth').forEach(el => {
            el.classList.add('disabled');
        });
    }
}

// Display API responses
function displayResponse(response, isError = false) {
    const responseDiv = document.createElement('div');
    responseDiv.className = isError ? 'response error' : 'response success';
    
    // Create timestamp
    const timestamp = document.createElement('div');
    timestamp.className = 'timestamp';
    timestamp.textContent = new Date().toLocaleTimeString();
    responseDiv.appendChild(timestamp);
    
    // Create content
    const content = document.createElement('pre');
    content.textContent = typeof response === 'string' 
        ? response 
        : JSON.stringify(response, null, 2);
    responseDiv.appendChild(content);
    
    // Add to responses container
    responsesElement.prepend(responseDiv);
    
    // Limit number of responses
    if (responsesElement.children.length > 5) {
        responsesElement.removeChild(responsesElement.lastChild);
    }
}

// API request helper function
async function apiRequest(endpoint, method = 'GET', data = null) {
    const headers = {
        'Content-Type': 'application/json',
    };
    
    if (authToken) {
        headers['Authorization'] = `Bearer ${authToken}`;
    }
    
    try {
        const response = await fetch(`${API_BASE_URL}${endpoint}`, {
            method,
            headers,
            body: data ? JSON.stringify(data) : null,
        });
        
        const responseData = await response.json();
        
        if (!response.ok) {
            throw new Error(responseData.message || `HTTP error! Status: ${response.status}`);
        }
        
        displayResponse(responseData);
        return responseData;
    } catch (error) {
        displayResponse(error.message, true);
        throw error;
    }
}

// Register a new user
async function register() {
    const email = document.getElementById('register-email').value;
    const password = document.getElementById('register-password').value;
    
    if (!email || !password) {
        displayResponse('Email and password are required', true);
        return;
    }
    
    try {
        const response = await apiRequest('/auth/register', 'POST', { 
            email, 
            password 
        });
        authToken = response.token;
        localStorage.setItem('token', authToken);
        updateAuthStatus();
    } catch (error) {
        console.error('Registration failed:', error);
    }
}

// Login user
async function login() {
    const email = document.getElementById('login-email').value;
    const password = document.getElementById('login-password').value;
    
    if (!email || !password) {
        displayResponse('Email and password are required', true);
        return;
    }
    
    try {
        const response = await apiRequest('/auth/login', 'POST', { 
            email, 
            password 
        });
        authToken = response.token;
        localStorage.setItem('token', authToken);
        updateAuthStatus();
    } catch (error) {
        console.error('Login failed:', error);
    }
}

// Get current user
async function getCurrentUser() {
    if (!authToken) {
        displayResponse('Authentication required', true);
        return;
    }
    
    try {
        await apiRequest('/auth/me');
    } catch (error) {
        console.error('Failed to get user:', error);
        // If authentication fails, clear token
        if (error.message.includes('401')) {
            authToken = '';
            localStorage.removeItem('token');
            updateAuthStatus();
        }
    }
}

// Logout user
function logout() {
    authToken = '';
    localStorage.removeItem('token');
    updateAuthStatus();
    displayResponse('Logged out successfully');
}

// Create a new post
async function createPost() {
    if (!authToken) {
        displayResponse('Authentication required', true);
        return;
    }
    
    const title = document.getElementById('post-title').value;
    const content = document.getElementById('post-content').value;
    
    if (!title || !content) {
        displayResponse('Title and content are required', true);
        return;
    }
    
    try {
        await apiRequest('/post', 'POST', { title, content });
        // Clear form
        document.getElementById('post-title').value = '';
        document.getElementById('post-content').value = '';
    } catch (error) {
        console.error('Failed to create post:', error);
    }
}

// Get all posts
async function getPosts() {
    try {
        await apiRequest('/post');
    } catch (error) {
        console.error('Failed to get posts:', error);
    }
}

// Get post by ID
async function getPostById() {
    const id = document.getElementById('post-id').value;
    
    if (!id) {
        displayResponse('Post ID is required', true);
        return;
    }
    
    try {
        await apiRequest(`/post/${id}`);
    } catch (error) {
        console.error('Failed to get post:', error);
    }
}

// Initialize app
function init() {
    // Set up event listeners
    document.getElementById('register-form').addEventListener('submit', (e) => {
        e.preventDefault();
        register();
    });
    
    document.getElementById('login-form').addEventListener('submit', (e) => {
        e.preventDefault();
        login();
    });
    
    document.getElementById('get-user-btn').addEventListener('click', getCurrentUser);
    document.getElementById('logout-btn').addEventListener('click', logout);
    
    document.getElementById('create-post-form').addEventListener('submit', (e) => {
        e.preventDefault();
        createPost();
    });
    
    document.getElementById('get-posts-btn').addEventListener('click', getPosts);
    
    document.getElementById('get-post-form').addEventListener('submit', (e) => {
        e.preventDefault();
        getPostById();
    });
    
    // Initialize authentication status
    updateAuthStatus();
}

// Run initialization when DOM is loaded
document.addEventListener('DOMContentLoaded', init); 