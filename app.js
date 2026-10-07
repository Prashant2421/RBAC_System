const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());

const users = new Map();
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me";

const createToken = (user) =>
  jwt.sign({ username: user.username, role: user.role }, JWT_SECRET, {
    expiresIn: "1h",
  });

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || (!authHeader.startsWith("Bearer ") && !authHeader.startsWith("JWT "))) {
    return res.status(401).json({ message: "Missing or invalid token" });
  }

  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : authHeader.slice(4);
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    return next();
  } catch (error) {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
};

const authorizeRoles = (...roles) => (req, res, next) => {
  if (!req.user || !roles.includes(req.user.role)) {
    return res.status(403).json({ message: "Forbidden" });
  }
  return next();
};

app.post("/register", async (req, res) => {
  const { username, password, role = "user" } = req.body;
  if (!username || !password) {
    return res.status(400).json({ message: "Username and password are required" });
  }

  if (users.has(username)) {
    return res.status(409).json({ message: "User already exists" });
  }

  const passwordHash = await bcrypt.hash(password, 10);
  users.set(username, { username, passwordHash, role });
  return res.status(201).json({ message: "User registered" });
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const user = users.get(username);
  if (!user) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  const passwordMatches = await bcrypt.compare(password, user.passwordHash);
  if (!passwordMatches) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  return res.json({ token: createToken(user) });
});

app.get("/profile", authenticateToken, (req, res) => {
  return res.json({ username: req.user.username, role: req.user.role });
});

app.get("/admin", authenticateToken, authorizeRoles("admin"), (req, res) => {
  return res.json({ message: "Welcome admin" });
});

const resetUsers = () => users.clear();

module.exports = { app, resetUsers };
