const express = require("express");
const Database = require("better-sqlite3");
const path = require("path");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const JWT_SECRET = "life_manager_secret";

const app = express();
app.use(cors());
app.use(express.json());

// ================= DB INIT =================
const dbPath = path.join(__dirname, "user.db");
const db = new Database(dbPath);

// ================= SERVER =================
app.listen(3000, () => {
  console.log("Server running on http://localhost:3000");
});

// ================= JWT MIDDLEWARE =================
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) return res.status(401).send({ message: "Token required" });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).send({ message: "Invalid token" });
    req.user = user;
    next();
  });
};

// ================= TEST =================
app.get("/", (req, res) => {
  res.send("Backend running successfully 🚀");
});

// ================= AUTH =================

// SIGNUP
app.post("/signup", (req, res) => {
  const { name, email, password } = req.body;

  const existingUser = db
    .prepare("SELECT * FROM users WHERE email = ?")
    .get(email);

  if (existingUser) {
    return res.status(400).send({ message: "User already exists" });
  }

  const hashedPassword = bcrypt.hashSync(password, 10);

  db.prepare(
    "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)"
  ).run(name, email, hashedPassword);

  res.send({ message: "User registered successfully" });
});

// LOGIN
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  const user = db
    .prepare("SELECT * FROM users WHERE email = ?")
    .get(email);

  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(400).send({ message: "Invalid email or password" });
  }

  const token = jwt.sign(
    { user_id: user.user_id },
    JWT_SECRET,
    { expiresIn: "1h" }
  );

  res.send({ message: "Login successful", token });
});

// ================= INCOME =================
app.post("/income", authenticateToken, (req, res) => {
  const { monthly_income } = req.body;
  const userId = req.user.user_id;

  const existing = db
    .prepare("SELECT * FROM income WHERE user_id = ?")
    .get(userId);

  if (existing) {
    db.prepare(
      "UPDATE income SET monthly_income = ? WHERE user_id = ?"
    ).run(monthly_income, userId);
  } else {
    db.prepare(
      "INSERT INTO income (user_id, monthly_income) VALUES (?, ?)"
    ).run(userId, monthly_income);
  }

  res.send({ message: "Income saved successfully" });
});

// ================= GOALS =================

// CREATE GOAL
app.post("/goals", authenticateToken, (req, res) => {
  const { title, category, target_amount, target_date } = req.body;
  const userId = req.user.user_id;

  db.prepare(
    `INSERT INTO goals 
     (user_id, title, category, target_amount, target_date, investment_amount)
     VALUES (?, ?, ?, ?, ?, 0)`
  ).run(userId, title, category, target_amount, target_date);

  res.send({ message: "Goal created successfully" });
});

// GET GOALS
app.get("/goals", authenticateToken, (req, res) => {
  const userId = req.user.user_id;

  const goals = db
    .prepare("SELECT * FROM goals WHERE user_id = ?")
    .all(userId);

  res.send(goals);
});

// ADD INVESTMENT (increment)
app.put("/goals/:goalId/invest", authenticateToken, (req, res) => {
  const { goalId } = req.params;
  const { investment_amount } = req.body;
  const userId = req.user.user_id;

  db.prepare(
    `UPDATE goals
     SET investment_amount = investment_amount + ?
     WHERE goal_id = ? AND user_id = ?`
  ).run(investment_amount, goalId, userId);

  res.send({ message: "Investment added" });
});

// EDIT INVESTMENT
app.put("/goals/:goalId/invest/edit", authenticateToken, (req, res) => {
  const { goalId } = req.params;
  const { investment_amount } = req.body;
  const userId = req.user.user_id;

  db.prepare(
    `UPDATE goals
     SET investment_amount = ?
     WHERE goal_id = ? AND user_id = ?`
  ).run(investment_amount, goalId, userId);

  res.send({ message: "Investment updated" });
});

// DELETE INVESTMENT
app.delete("/goals/:goalId/invest", authenticateToken, (req, res) => {
  const { goalId } = req.params;
  const userId = req.user.user_id;

  db.prepare(
    `UPDATE goals
     SET investment_amount = 0
     WHERE goal_id = ? AND user_id = ?`
  ).run(goalId, userId);

  res.send({ message: "Investment deleted" });
});

// ================= SUMMARY =================
app.get("/summary", authenticateToken, (req, res) => {
  const userId = req.user.user_id;

  const incomeRow = db
    .prepare("SELECT monthly_income FROM income WHERE user_id = ?")
    .get(userId);

  const goals = db
    .prepare("SELECT title, investment_amount FROM goals WHERE user_id = ?")
    .all(userId);

  const totalInvestment = goals.reduce(
    (sum, g) => sum + g.investment_amount,
    0
  );

  const income = incomeRow?.monthly_income || 0;

  res.send({
    income,
    totalInvestment,
    savings: income - totalInvestment,
    goals
  });
});
