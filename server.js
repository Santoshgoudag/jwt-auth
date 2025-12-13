require("dotenv").config();
const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();

// In-memory user array
let users = [];

// REGISTER ROUTE
// Example: /register?email=a@gmail.com&password=123
app.get("/register", async (req, res) => {
    const { email, password } = req.query;

    if (!email || !password)
        return res.send("Email and password required");

    // Check duplicate email
    const exists = users.find(u => u.email === email);
    if (exists) return res.send("Email already registered");

    // Hash password
    const hashed = await bcrypt.hash(password, 10);

    users.push({ email, password: hashed });

    res.send("Registration successful");
});

// LOGIN ROUTE
// Example: /login?email=a@gmail.com&password=123
app.get("/login", async (req, res) => {
    const { email, password } = req.query;

    const user = users.find(u => u.email === email);
    if (!user) return res.send("Invalid email or password");

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.send("Invalid email or password");

    // Generate token (expires in 10 minutes)
    const token = jwt.sign(
        { email },
        process.env.JWT_SECRET,
        { expiresIn: "10m" }
    );

    res.send(token);
});

// PROTECTED ROUTE
// Example: /invoke?token=xxxxx
app.get("/invoke", (req, res) => {
    const { token } = req.query;

    if (!token) return res.send("Access denied");

    try {
        jwt.verify(token, process.env.JWT_SECRET);
        res.send("Function invoked successfully");
    } catch (err) {
        res.send("Access denied");
    }
});

app.listen(3000, () => console.log("Server running on port 3000"));
