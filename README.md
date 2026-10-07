# RBAC_System
A secure Node.js REST API demonstrating role-based access control with JWT authentication, bcrypt password hashing, MongoDB, Express, and protected user roles.

## Run

```bash
npm install
npm start
```

## API Endpoints

- `POST /register` `{ username, password, role? }`
- `POST /login` `{ username, password }` returns `{ token }`
- `GET /profile` requires auth header: `Authorization: JWT <token>`
- `GET /admin` requires `admin` role
