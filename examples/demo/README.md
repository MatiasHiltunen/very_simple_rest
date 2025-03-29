# REST Macro Demo

This is a demonstration of the REST Macro library, showing how to easily create RESTful APIs with CRUD operations, authentication, and role-based access control.

## Features Demonstrated

- **REST API Generation**: Automatically generate CRUD endpoints from Rust structs
- **Authentication**: JWT-based authentication with role-based access control
- **Relationships**: Foreign key relationships and nested routes
- **Frontend Client**: A simple web client to interact with the API

## Running the Demo

```bash
# Start the server
cargo run

# The server will be available at:
# http://localhost:8080
```

## Project Structure

- `src/main.rs` - The main server implementation
- `public/` - Frontend client files
  - `index.html` - The HTML interface
  - `app.js` - JavaScript code for interacting with the API
  - `README.md` - Documentation for the frontend client

## API Models

The demo implements the following models:

### User

```rust
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, RestApi)]
#[rest_api(table = "users", id = "id", db = "sqlite")]
#[require_role(read = "admin", update = "admin", delete = "admin")]
pub struct User {
    pub id: Option<i64>,
    pub email: String,
    pub password_hash: String,
    pub role: String,
}
```

### Post

```rust
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, RestApi)]
#[rest_api(table = "posts", id = "id", db = "sqlite")]
#[require_role(read = "user", update = "user", delete = "user")]
pub struct Post {
    pub id: Option<i64>,
    pub title: String,
    pub content: String,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}
```

### Comment

```rust
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, RestApi)]
#[rest_api(table = "comments", id = "id", db = "sqlite")]
#[require_role(read = "user", update = "user", delete = "user")]
pub struct Comment {
    pub id: Option<i64>,
    pub title: String,
    pub content: String,
    #[relation(foreign_key = "post_id", references = "posts.id", nested_route = "true")]
    pub post_id: i64,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}
```

## Testing the API

Open the web client at http://localhost:8080 to interact with the API through a user interface, or use curl to make direct API calls:

```bash
# Register a new user
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "password123"}'

# Login to get a token
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "password123"}'

# Create a post (with token)
curl -X POST http://localhost:8080/api/post \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"title": "My First Post", "content": "Hello, world!"}'
```