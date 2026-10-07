const test = require("node:test");
const assert = require("node:assert/strict");
const request = require("supertest");
const { app, resetUsers } = require("../app");

test("register and login returns JWT token", async () => {
  resetUsers();
  await request(app)
    .post("/register")
    .send({ username: "alice", password: "password123", role: "admin" })
    .expect(201);

  const loginResponse = await request(app)
    .post("/login")
    .send({ username: "alice", password: "password123" })
    .expect(200);

  assert.ok(loginResponse.body.token);
});

test("admin endpoint denies non-admin role", async () => {
  resetUsers();
  await request(app)
    .post("/register")
    .send({ username: "bob", password: "password123", role: "user" })
    .expect(201);

  const loginResponse = await request(app)
    .post("/login")
    .send({ username: "bob", password: "password123" })
    .expect(200);

  await request(app)
    .get("/admin")
    .set("Authorization", "JWT " + loginResponse.body.token)
    .expect(403);
});

test("profile endpoint requires valid JWT", async () => {
  resetUsers();
  await request(app).get("/profile").expect(401);
});

test("admin endpoint allows admin role", async () => {
  resetUsers();
  await request(app)
    .post("/register")
    .send({ username: "carol", password: "password123", role: "admin" })
    .expect(201);

  const loginResponse = await request(app)
    .post("/login")
    .send({ username: "carol", password: "password123" })
    .expect(200);

  await request(app)
    .get("/admin")
    .set("Authorization", "JWT " + loginResponse.body.token)
    .expect(200);
});
