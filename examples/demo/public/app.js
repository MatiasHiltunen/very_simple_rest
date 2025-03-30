// API client for the REST Macro Demo
const API_URL = 'http://localhost:8080/api';
const ROOT_URL = 'http://localhost:8080';
let authToken = localStorage.getItem('authToken') || '';
let userRole = '';

// Pagination state
const paginationState = {
    users: { page: 1, limit: 10 },
    posts: { page: 1, limit: 10 },
    comments: { page: 1, limit: 10 }
};

// DOM Elements
const authOutput = document.getElementById('authOutput');
const postsOutput = document.getElementById('postsOutput');
const commentsOutput = document.getElementById('commentsOutput');
const userOutput = document.getElementById('userOutput');
const tokenDisplay = document.getElementById('tokenDisplay');
const adminPanel = document.getElementById('adminPanel');
const usersList = document.getElementById('usersList');

// Page info elements
const usersPageInfo = document.getElementById('usersPageInfo');
const postsPageInfo = document.getElementById('postsPageInfo');
const commentsPageInfo = document.getElementById('commentsPageInfo');

// Global functions for HTML events
window.editUser = editUser;
window.deleteUser = deleteUser;
window.editPost = editPost;
window.deletePost = deletePost;
window.editComment = editComment;
window.deleteComment = deleteComment;

// Show token if it exists
if (authToken) {
    tokenDisplay.innerHTML = `<span class="success">Token loaded from storage!</span>`;
    // Get user info
    fetchUserInfo();
}

// Event Listeners - Auth
document.getElementById('registerBtn').addEventListener('click', register);
document.getElementById('loginBtn').addEventListener('click', login);
document.getElementById('logoutBtn').addEventListener('click', logout);

// Event Listeners - Posts
document.getElementById('createPostBtn').addEventListener('click', createPost);
document.getElementById('getPostsBtn').addEventListener('click', () => getPosts());
document.getElementById('searchPostsBtn').addEventListener('click', searchPosts);
document.getElementById('prevPostsPage').addEventListener('click', () => changePage('posts', -1));
document.getElementById('nextPostsPage').addEventListener('click', () => changePage('posts', 1));

// Event Listeners - Comments
document.getElementById('createCommentBtn').addEventListener('click', createComment);
document.getElementById('getCommentsBtn').addEventListener('click', () => getComments());
document.getElementById('getPostCommentsBtn').addEventListener('click', getPostComments);
document.getElementById('searchCommentsBtn').addEventListener('click', searchComments);
document.getElementById('prevCommentsPage').addEventListener('click', () => changePage('comments', -1));
document.getElementById('nextCommentsPage').addEventListener('click', () => changePage('comments', 1));

// Event Listeners - Users (Admin)
document.getElementById('createUserBtn').addEventListener('click', createUser);
document.getElementById('searchUsersBtn').addEventListener('click', searchUsers);
document.getElementById('prevUsersPage').addEventListener('click', () => changePage('users', -1));
document.getElementById('nextUsersPage').addEventListener('click', () => changePage('users', 1));

// Helper functions
function displayError(outputElement, message) {
    outputElement.innerHTML = `<span class="error">Error: ${message}</span>`;
}

function displaySuccess(outputElement, message) {
    outputElement.innerHTML = `<span class="success">${message}</span>`;
}

function displayJSON(outputElement, data) {
    try {
        // For mobile-friendly display, format complex objects better
        if (window.innerWidth <= 768) {
            outputElement.innerHTML = formatDataForMobile(data);
        } else {
            // Desktop formatting with action buttons for arrays
            if (Array.isArray(data) && data.length > 0) {
                let formattedOutput = '';
                
                data.forEach((item, index) => {
                    // Format the JSON for this item
                    let jsonString = JSON.stringify(item, null, 2);
                    
                    // Determine if this is a post or comment based on keys
                    const itemType = item.hasOwnProperty('post_id') ? 'comment' : 'post';
                    
                    // Add buttons at the end
                    formattedOutput += `<div style="margin-bottom: 16px; padding-bottom: 16px; border-bottom: 1px solid #eee">`;
                    formattedOutput += `<pre>${jsonString}</pre>`;
                    
                    if (item.id) {
                        formattedOutput += `<div style="margin-top: 8px">
                            <button onclick="${itemType === 'post' ? 'editPost' : 'editComment'}(${item.id})" class="secondary">Edit</button>
                            <button onclick="${itemType === 'post' ? 'deletePost' : 'deleteComment'}(${item.id})" class="danger">Delete</button>
                        </div>`;
                    }
                    
                    formattedOutput += `</div>`;
                });
                
                outputElement.innerHTML = formattedOutput;
            } else {
                // Not an array or empty, just display as-is
                outputElement.innerHTML = JSON.stringify(data, null, 2);
            }
            
            // Make sure the output element has the right CSS for desktop
            outputElement.style.maxWidth = '100%';
            outputElement.style.overflowX = 'hidden';
        }
    } catch (error) {
        outputElement.innerHTML = `<span class="error">Error formatting data: ${error.message}</span>`;
    }
}

// Format data for better mobile display
function formatDataForMobile(data) {
    if (!Array.isArray(data)) {
        return JSON.stringify(data, null, 2);
    }
    
    let html = '';
    
    data.forEach((item, index) => {
        html += `<div style="margin-bottom: 12px; padding: 8px; border-bottom: 1px solid #eee;">`;
        html += `<div style="font-weight: bold; color: #3f51b5; margin-bottom: 4px;">Item #${index + 1}</div>`;
        
        Object.entries(item).forEach(([key, value]) => {
            // Skip long content fields or truncate them
            if (key === 'content' && typeof value === 'string' && value.length > 50) {
                value = value.substring(0, 50) + '...';
            }
            
            // Format dates nicely
            if (key.includes('_at') && value) {
                try {
                    const date = new Date(value);
                    if (!isNaN(date)) {
                        value = date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
                    }
                } catch (e) {
                    // Keep original value if date parsing fails
                }
            }
            
            html += `<div><span style="color: #666; font-weight: 500;">${key}:</span> ${value}</div>`;
        });
        
        // Add edit/delete buttons
        if (item.id) {
            const itemType = item.hasOwnProperty('post_id') ? 'comment' : 'post';
            html += `<div style="display: flex; flex-wrap: wrap; gap: 8px; margin-top: 10px;">
                <button onclick="${itemType === 'post' ? 'editPost' : 'editComment'}(${item.id})" class="secondary" style="padding: 4px 8px; font-size: 12px;">Edit</button>
                <button onclick="${itemType === 'post' ? 'deletePost' : 'deleteComment'}(${item.id})" class="danger" style="padding: 4px 8px; font-size: 12px;">Delete</button>
            </div>`;
        }
        
        html += `</div>`;
    });
    
    return html;
}

function updatePageInfo(type) {
    const state = paginationState[type];
    const infoElement = document.getElementById(`${type}PageInfo`);
    if (infoElement) {
        infoElement.textContent = `Page ${state.page}`;
    }
}

function changePage(type, change) {
    paginationState[type].page = Math.max(1, paginationState[type].page + change);
    updatePageInfo(type);
    
    // Refresh the current view based on type
    switch (type) {
        case 'users':
            searchUsers();
            break;
        case 'posts':
            searchPosts();
            break;
        case 'comments':
            searchComments();
            break;
    }
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
        const response = await fetchJson(`${API_URL}/auth/register`, {
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
        const response = await fetchJson(`${API_URL}/auth/login`, {
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

async function logout() {
    authToken = '';
    userRole = '';
    localStorage.removeItem('authToken');
    tokenDisplay.innerHTML = '';
    authOutput.innerHTML = 'Logged out successfully!';
    
    // Hide admin panel
    adminPanel.classList.add('hidden');
}

async function fetchUserInfo() {
    if (!authToken) {
        displayError(authOutput, 'Not logged in');
        return;
    }
    
    try {
        const userData = await fetchJson(`${API_URL}/auth/me`, {
            headers: { 'Authorization': `Bearer ${authToken}` }
        });
        
        userRole = userData.roles[0];
        authOutput.innerHTML = `Logged in as: ${userRole} role`;
        
        // Show admin panel if user is admin
        if (userRole === 'admin') {
            adminPanel.classList.remove('hidden');
            // Load initial user list
            searchUsers();
        } else {
            adminPanel.classList.add('hidden');
        }
        
        // Initialize searches with default values
        searchPosts();
        searchComments();
    } catch (error) {
        displayError(authOutput, 'Failed to get user info: ' + error.message);
    }
}

// User management functions (Admin only)
async function searchUsers() {
    if (userRole !== 'admin' || !authToken) {
        return;
    }
    
    const searchTerm = document.getElementById('userSearch').value;
    const sortField = document.getElementById('userSortField').value;
    const sortDir = document.getElementById('userSortDir').value;
    const { page, limit } = paginationState.users;
    
    try {
        let url = `${API_URL}/user?page=${page}&limit=${limit}`;
        
        if (sortField) {
            url += `&order_by=${sortField}&order_dir=${sortDir}`;
        }
        
        if (searchTerm) {
            url += `&search=${encodeURIComponent(searchTerm)}`;
        }
        
        const users = await fetchJson(url, {
            headers: { 'Authorization': `Bearer ${authToken}` }
        });
        
        renderUsersList(users);
    } catch (error) {
        displayError(userOutput, error.message);
    }
}

function renderUsersList(users) {
    if (!users || !users.length) {
        usersList.innerHTML = '<p>No users found</p>';
        return;
    }
    
    let html = '';
    users.forEach(user => {
        html += `
            <div class="user-item">
                <div style="margin-bottom: 8px;">
                    <strong style="color: #3f51b5;">${user.email}</strong>
                </div>
                <div style="display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 12px;">
                    <span class="badge" style="display: inline-block; padding: 4px 8px; border-radius: 4px; background-color: ${user.role === 'admin' ? '#ffcdd2' : '#e8f5e9'}; color: ${user.role === 'admin' ? '#c62828' : '#2e7d32'}; font-weight: 500;">
                        ${user.role}
                    </span>
                    <span style="color: #666; font-size: 0.9rem;">ID: ${user.id || 'N/A'}</span>
                </div>
                <div style="display: flex; flex-wrap: wrap; gap: 8px;">
                    <button onclick="editUser(${user.id})" class="secondary">Edit</button>
                    <button onclick="deleteUser(${user.id})" class="danger">Delete</button>
                </div>
            </div>
        `;
    });
    
    usersList.innerHTML = html;
}

async function createUser() {
    if (userRole !== 'admin' || !authToken) {
        displayError(userOutput, 'Admin role required');
        return;
    }
    
    const email = document.getElementById('newUserEmail').value;
    const password = document.getElementById('newUserPassword').value;
    const role = document.getElementById('newUserRole').value;
    
    if (!email || !password || !role) {
        displayError(userOutput, 'All fields are required');
        return;
    }
    
    try {
        const data = { email, password_hash: password, role };
        const response = await fetchJson(`${API_URL}/user`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            },
            body: JSON.stringify(data)
        });
        
        displaySuccess(userOutput, 'User created successfully!');
        document.getElementById('newUserEmail').value = '';
        document.getElementById('newUserPassword').value = '';
        
        // Refresh user list
        searchUsers();
    } catch (error) {
        displayError(userOutput, error.message);
    }
}

async function editUser(userId) {
    if (userRole !== 'admin' || !authToken) {
        return;
    }
    
    try {
        // Fetch current user data
        const user = await fetchJson(`${API_URL}/user/${userId}`, {
            headers: { 'Authorization': `Bearer ${authToken}` }
        });
        
        // Prompt for new role
        const newRole = prompt(`Edit role for ${user.email}:`, user.role);
        if (!newRole) return;
        
        // Update user
        const data = { ...user, role: newRole };
        await fetchJson(`${API_URL}/user/${userId}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            },
            body: JSON.stringify(data)
        });
        
        displaySuccess(userOutput, 'User updated successfully!');
        
        // Refresh user list
        searchUsers();
    } catch (error) {
        displayError(userOutput, error.message);
    }
}

async function deleteUser(userId) {
    if (userRole !== 'admin' || !authToken) {
        return;
    }
    
    if (!confirm('Are you sure you want to delete this user?')) {
        return;
    }
    
    try {
        await fetchJson(`${API_URL}/user/${userId}`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${authToken}` }
        });
        
        displaySuccess(userOutput, 'User deleted successfully!');
        
        // Refresh user list
        searchUsers();
    } catch (error) {
        displayError(userOutput, error.message);
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
        searchPosts();
    } catch (error) {
        displayError(postsOutput, error.message);
    }
}

async function getPosts() {
    paginationState.posts.page = 1;
    updatePageInfo('posts');
    searchPosts();
}

async function searchPosts() {
    const searchTerm = document.getElementById('postSearch').value;
    const sortField = document.getElementById('postSortField').value;
    const sortDir = document.getElementById('postSortDir').value;
    paginationState.posts.limit = parseInt(document.getElementById('postLimit').value);
    const { page, limit } = paginationState.posts;
    
    try {
        let url = `${API_URL}/post?page=${page}&limit=${limit}`;
        
        if (sortField) {
            url += `&order_by=${sortField}&order_dir=${sortDir}`;
        }
        
        if (searchTerm) {
            url += `&search=${encodeURIComponent(searchTerm)}`;
        }
        
        const posts = await fetchJson(url, {
            headers: authToken ? { 'Authorization': `Bearer ${authToken}` } : {}
        });
        
        displayJSON(postsOutput, posts);
    } catch (error) {
        displayError(postsOutput, error.message);
    }
}

async function editPost(postId) {
    if (!authToken) {
        displayError(postsOutput, 'You must be logged in to edit posts');
        return;
    }
    
    try {
        // First, fetch the post data
        const post = await fetchJson(`${API_URL}/post/${postId}`, {
            headers: { 'Authorization': `Bearer ${authToken}` }
        });
        
        // Prompt for new values
        const newTitle = prompt('Edit title:', post.title);
        if (newTitle === null) return; // User cancelled
        
        const newContent = prompt('Edit content:', post.content);
        if (newContent === null) return; // User cancelled
        
        // Update with new values
        const updatedPost = {
            ...post,
            title: newTitle,
            content: newContent
        };
        
        await fetchJson(`${API_URL}/post/${postId}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            },
            body: JSON.stringify(updatedPost)
        });
        
        displaySuccess(postsOutput, 'Post updated successfully!');
        
        // Refresh posts list
        searchPosts();
    } catch (error) {
        displayError(postsOutput, error.message);
    }
}

async function deletePost(postId) {
    if (!authToken) {
        displayError(postsOutput, 'You must be logged in to delete posts');
        return;
    }
    
    if (!confirm('Are you sure you want to delete this post? This will also delete all associated comments.')) {
        return;
    }
    
    try {
        await fetchJson(`${API_URL}/post/${postId}`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${authToken}` }
        });
        
        displaySuccess(postsOutput, 'Post deleted successfully!');
        
        // Refresh posts list
        searchPosts();
        
        // Also refresh comments list since comments for this post are now gone
        searchComments();
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
        searchComments();
    } catch (error) {
        displayError(commentsOutput, error.message);
    }
}

async function getComments() {
    paginationState.comments.page = 1;
    updatePageInfo('comments');
    searchComments();
}

async function searchComments() {
    const searchTerm = document.getElementById('commentSearch').value;
    const sortField = document.getElementById('commentSortField').value;
    const sortDir = document.getElementById('commentSortDir').value;
    paginationState.comments.limit = parseInt(document.getElementById('commentLimit').value);
    const { page, limit } = paginationState.comments;
    
    try {
        let url = `${API_URL}/comment?page=${page}&limit=${limit}`;
        
        if (sortField) {
            url += `&order_by=${sortField}&order_dir=${sortDir}`;
        }
        
        if (searchTerm) {
            url += `&search=${encodeURIComponent(searchTerm)}`;
        }
        
        const comments = await fetchJson(url, {
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
    
    paginationState.comments.page = 1;
    updatePageInfo('comments');
    
    const searchTerm = document.getElementById('commentSearch').value;
    const sortField = document.getElementById('commentSortField').value;
    const sortDir = document.getElementById('commentSortDir').value;
    paginationState.comments.limit = parseInt(document.getElementById('commentLimit').value);
    const { page, limit } = paginationState.comments;
    
    try {
        let url = `${API_URL}/post/${postId}/comment?page=${page}&limit=${limit}`;
        
        if (sortField) {
            url += `&order_by=${sortField}&order_dir=${sortDir}`;
        }
        
        if (searchTerm) {
            url += `&search=${encodeURIComponent(searchTerm)}`;
        }
        
        const comments = await fetchJson(url, {
            headers: authToken ? { 'Authorization': `Bearer ${authToken}` } : {}
        });
        
        displayJSON(commentsOutput, comments);
    } catch (error) {
        displayError(commentsOutput, error.message);
    }
}

async function editComment(commentId) {
    if (!authToken) {
        displayError(commentsOutput, 'You must be logged in to edit comments');
        return;
    }
    
    try {
        // First, fetch the comment data
        const comment = await fetchJson(`${API_URL}/comment/${commentId}`, {
            headers: { 'Authorization': `Bearer ${authToken}` }
        });
        
        // Prompt for new values
        const newTitle = prompt('Edit title:', comment.title);
        if (newTitle === null) return; // User cancelled
        
        const newContent = prompt('Edit content:', comment.content);
        if (newContent === null) return; // User cancelled
        
        // Update with new values
        const updatedComment = {
            ...comment,
            title: newTitle,
            content: newContent
        };
        
        await fetchJson(`${API_URL}/comment/${commentId}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            },
            body: JSON.stringify(updatedComment)
        });
        
        displaySuccess(commentsOutput, 'Comment updated successfully!');
        
        // Refresh comments list
        searchComments();
    } catch (error) {
        displayError(commentsOutput, error.message);
    }
}

async function deleteComment(commentId) {
    if (!authToken) {
        displayError(commentsOutput, 'You must be logged in to delete comments');
        return;
    }
    
    if (!confirm('Are you sure you want to delete this comment?')) {
        return;
    }
    
    try {
        await fetchJson(`${API_URL}/comment/${commentId}`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${authToken}` }
        });
        
        displaySuccess(commentsOutput, 'Comment deleted successfully!');
        
        // Refresh comments list
        searchComments();
    } catch (error) {
        displayError(commentsOutput, error.message);
    }
}

// Add window resize listener to reformat JSON output when screen size changes
window.addEventListener('resize', () => {
    // If any data is displayed in the output areas, refresh them
    if (postsOutput.innerHTML) {
        searchPosts();
    }
    if (commentsOutput.innerHTML) {
        searchComments();
    }
}); 