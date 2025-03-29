// API client for the REST Macro Demo
const API_URL = 'http://localhost:8080/api';
const ROOT_URL = 'http://localhost:8080';
let authToken = localStorage.getItem('authToken') || '';
let userRole = '';

// DOM Elements
const authOutput = document.getElementById('authOutput');
const postsOutput = document.getElementById('postsOutput');
const commentsOutput = document.getElementById('commentsOutput');
const tokenDisplay = document.getElementById('tokenDisplay');

// Show token if it exists
if (authToken) {
    tokenDisplay.innerHTML = `<span class="success">Token loaded from storage!</span>`;
    // Get user info
    fetchUserInfo();
}

// Event Listeners
document.getElementById('registerBtn').addEventListener('click', register);
document.getElementById('loginBtn').addEventListener('click', login);
document.getElementById('createPostBtn').addEventListener('click', createPost);
document.getElementById('getPostsBtn').addEventListener('click', getPosts);
document.getElementById('createCommentBtn').addEventListener('click', createComment);
document.getElementById('getCommentsBtn').addEventListener('click', getComments);
document.getElementById('getPostCommentsBtn').addEventListener('click', getPostComments);

// Helper functions
function displayError(outputElement, message) {
    outputElement.innerHTML = `<span class="error">Error: ${message}</span>`;
}

function displaySuccess(outputElement, message) {
    outputElement.innerHTML = `<span class="success">${message}</span>`;
}

function displayJSON(outputElement, data) {
    outputElement.innerHTML = JSON.stringify(data, null, 2);
}

async function fetchJson(url, options = {}) {
    try {
        const response = await fetch(url, options);
        const contentType = response.headers.get('content-type');
        
        if (response.status >= 400) {
            if (contentType && contentType.includes('application/json')) {
                const errorData = await response.json();
                throw new Error(errorData.message || 'API Error');
            } else {
                const errorText = await response.text();
                throw new Error(errorText || `HTTP Error ${response.status}`);
            }
        }
        
        if (contentType && contentType.includes('application/json')) {
            return await response.json();
        }
        
        return await response.text();
    } catch (error) {
        throw error;
    }
}

// Auth functions
async function register() {
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    
    if (!email || !password) {
        displayError(authOutput, 'Email and password are required');
        return;
    }
    
    try {
        const data = { email, password };
        const response = await fetchJson(`${ROOT_URL}/auth/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        });
        
        displaySuccess(authOutput, 'Registration successful! Please login.');
    } catch (error) {
        displayError(authOutput, error.message);
    }
}

async function login() {
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    
    if (!email || !password) {
        displayError(authOutput, 'Email and password are required');
        return;
    }
    
    try {
        const data = { email, password };
        const response = await fetchJson(`${ROOT_URL}/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        });
        
        authToken = response.token;
        localStorage.setItem('authToken', authToken);
        displaySuccess(authOutput, 'Login successful!');
        tokenDisplay.innerHTML = `<span class="success">Auth token received and stored!</span>`;
        
        // Get user info after login
        fetchUserInfo();
    } catch (error) {
        displayError(authOutput, error.message);
    }
}

async function fetchUserInfo() {
    if (!authToken) {
        displayError(authOutput, 'Not logged in');
        return;
    }
    
    try {
        const userData = await fetchJson(`${ROOT_URL}/auth/me`, {
            headers: { 'Authorization': `Bearer ${authToken}` }
        });
        
        userRole = userData.roles[0];
        authOutput.innerHTML = `Logged in as: ${userRole} role`;
    } catch (error) {
        displayError(authOutput, 'Failed to get user info: ' + error.message);
    }
}

// Post functions
async function createPost() {
    if (!authToken) {
        displayError(postsOutput, 'You must be logged in to create posts');
        return;
    }
    
    const title = document.getElementById('postTitle').value;
    const content = document.getElementById('postContent').value;
    
    if (!title || !content) {
        displayError(postsOutput, 'Title and content are required');
        return;
    }
    
    try {
        const data = { title, content };
        const response = await fetchJson(`${API_URL}/post`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            },
            body: JSON.stringify(data)
        });
        
        displaySuccess(postsOutput, 'Post created successfully!');
        document.getElementById('postTitle').value = '';
        document.getElementById('postContent').value = '';
        
        // Refresh posts list
        getPosts();
    } catch (error) {
        displayError(postsOutput, error.message);
    }
}

async function getPosts() {
    try {
        const posts = await fetchJson(`${API_URL}/post`, {
            headers: authToken ? { 'Authorization': `Bearer ${authToken}` } : {}
        });
        
        displayJSON(postsOutput, posts);
    } catch (error) {
        displayError(postsOutput, error.message);
    }
}

// Comment functions
async function createComment() {
    if (!authToken) {
        displayError(commentsOutput, 'You must be logged in to create comments');
        return;
    }
    
    const postId = document.getElementById('postId').value;
    const title = document.getElementById('commentTitle').value;
    const content = document.getElementById('commentContent').value;
    
    if (!postId || !title || !content) {
        displayError(commentsOutput, 'Post ID, title and content are required');
        return;
    }
    
    try {
        const data = { post_id: parseInt(postId), title, content };
        const response = await fetchJson(`${API_URL}/comment`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            },
            body: JSON.stringify(data)
        });
        
        displaySuccess(commentsOutput, 'Comment created successfully!');
        document.getElementById('commentTitle').value = '';
        document.getElementById('commentContent').value = '';
        
        // Refresh comments list
        getComments();
    } catch (error) {
        displayError(commentsOutput, error.message);
    }
}

async function getComments() {
    try {
        const comments = await fetchJson(`${API_URL}/comment`, {
            headers: authToken ? { 'Authorization': `Bearer ${authToken}` } : {}
        });
        
        displayJSON(commentsOutput, comments);
    } catch (error) {
        displayError(commentsOutput, error.message);
    }
}

async function getPostComments() {
    const postId = document.getElementById('postId').value;
    
    if (!postId) {
        displayError(commentsOutput, 'Post ID is required');
        return;
    }
    
    try {
        const comments = await fetchJson(`${API_URL}/post/${postId}/comment`, {
            headers: authToken ? { 'Authorization': `Bearer ${authToken}` } : {}
        });
        
        displayJSON(commentsOutput, comments);
    } catch (error) {
        displayError(commentsOutput, error.message);
    }
} 