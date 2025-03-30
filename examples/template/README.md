# {{project_name}}

{{description}}

This project was generated using [very_simple_rest](https://github.com/MatiasHiltunen/very_simple_rest), a lightweight framework for building REST APIs with Rust.

## Features

- RESTful API with automatic CRUD endpoints
- JWT authentication and role-based access control
- Database integration with SQLite (configurable for PostgreSQL/MySQL)
- Structured logging
- Environment-based configuration

## Getting Started

### Prerequisites

- Rust (latest stable)
- SQLite (or your preferred database)

### Installation

1. Clone the repository
   ```bash
   git clone {{repository_url}}
   cd {{project_name}}
   ```

2. Set up environment variables
   ```bash
   cp .env.example .env
   # Edit .env with your settings
   ```

3. Run the application
   ```bash
   cargo run
   ```

4. Visit the API at `http://localhost:8080/api`

## API Endpoints

### Authentication

- `POST /api/auth/register` - Create a new user account
- `POST /api/auth/login` - Get a JWT token
- `GET /api/auth/me` - Get current user info

### Users (Admin Only)

- `GET /api/user` - List all users
- `GET /api/user/{id}` - Get user by ID
- `POST /api/user` - Create a new user
- `PUT /api/user/{id}` - Update user
- `DELETE /api/user/{id}` - Delete user

### Posts (User Role Required)

- `GET /api/post` - List all posts
- `GET /api/post/{id}` - Get post by ID
- `POST /api/post` - Create a new post
- `PUT /api/post/{id}` - Update post
- `DELETE /api/post/{id}` - Delete post

## Configuration

All configuration is done through environment variables. See `.env.example` for available options.

## License

{{license}}

## Author

{{author}} 