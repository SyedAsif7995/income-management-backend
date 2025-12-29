const express = require("express");
const { open } = require("sqlite");
const sqlite3 = require("sqlite3");
const path = require("path");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const JWT_SECRET = "life_manager_secret";

const app = express();
app.use(cors());
app.use(express.json());

const dbPath = path.join(__dirname, "user.db");
let db;

// ================= DB INITIALIZATION =================
const initializeDB = async () => {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    });

    app.listen(3000, () => {
      console.log("Server running on http://localhost:3000");
    });
  } catch (error) {
    console.log("Database Error:", error.message);
    process.exit(1);
  }
};
initializeDB();

// ================= JWT MIDDLEWARE =================
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).send({ message: "Token required" });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).send({ message: "Invalid token" });
    }
    req.user = user;
    next();
  });
};

// ================= TEST ROUTE =================
app.get("/", (req, res) => {
  res.send("Backend running successfully 🚀");
});

// ================= AUTH =================

// SIGNUP
app.post("/signup", async (req, res) => {
  const { name, email, password } = req.body;

  const existingUser = await db.get(
    "SELECT * FROM users WHERE email = ?",
    [email]
  );

  if (existingUser) {
    return res.status(400).send({ message: "User already exists" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  await db.run(
    "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
    [name, email, hashedPassword]
  );

  res.send({ message: "User registered successfully" });
});

// LOGIN
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const user = await db.get(
    "SELECT * FROM users WHERE email = ?",
    [email]
  );

  if (!user) {
    return res.status(400).send({ message: "Invalid email or password" });
  }

  const isPasswordValid = await bcrypt.compare(
    password,
    user.password_hash
  );

  if (!isPasswordValid) {
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
app.post("/income", authenticateToken, async (req, res) => {
  const { monthly_income } = req.body;
  const userId = req.user.user_id;

  if (!monthly_income || monthly_income <= 0) {
    return res.status(400).send({ message: "Invalid income" });
  }

  const existing = await db.get(
    "SELECT * FROM income WHERE user_id = ?",
    [userId]
  );

  if (existing) {
    await db.run(
      "UPDATE income SET monthly_income = ? WHERE user_id = ?",
      [monthly_income, userId]
    );
  } else {
    await db.run(
      "INSERT INTO income (user_id, monthly_income) VALUES (?, ?)",
      [userId, monthly_income]
    );
  }

  res.send({ message: "Income saved successfully" });
});

// ================= GOALS CRUD =================

// CREATE GOAL
app.post("/goals", authenticateToken, async (req, res) => {
  const { title, category, target_amount, target_date } = req.body;
  const userId = req.user.user_id;

  await db.run(
    `INSERT INTO goals
     (user_id, title, category, target_amount, target_date, investment_amount)
     VALUES (?, ?, ?, ?, ?, 0)`,
    [userId, title, category, target_amount, target_date]
  );

  res.send({ message: "Goal created successfully" });
});

// GET ALL GOALS
app.get("/goals", authenticateToken, async (req, res) => {
  const userId = req.user.user_id;

  const goals = await db.all(
    "SELECT * FROM goals WHERE user_id = ?",
    [userId]
  );

  res.send(goals);
});

// UPDATE GOAL
app.put("/goals/:goalId", authenticateToken, async (req, res) => {
  const { goalId } = req.params;
  const { title, category, target_amount, target_date } = req.body;
  const userId = req.user.user_id;

  const result = await db.run(
    `UPDATE goals
     SET title=?, category=?, target_amount=?, target_date=?, updated_at=CURRENT_TIMESTAMP
     WHERE goal_id=? AND user_id=?`,
    [title, category, target_amount, target_date, goalId, userId]
  );

  if (result.changes === 0) {
    return res.status(404).send({ message: "Goal not found" });
  }

  res.send({ message: "Goal updated successfully" });
});

// DELETE GOAL
app.delete("/goals/:goalId", authenticateToken, async (req, res) => {
  const { goalId } = req.params;
  const userId = req.user.user_id;

  await db.run(
    "DELETE FROM goals WHERE goal_id=? AND user_id=?",
    [goalId, userId]
  );

  res.send({ message: "Goal deleted successfully" });
});

// ================= INVESTMENT (ORDER MATTERS) =================

// EDIT INVESTMENT (REPLACE)
app.put("/goals/:goalId/invest/edit", authenticateToken, async (req, res) => {
  const { goalId } = req.params;
  const { investment_amount } = req.body;
  const userId = req.user.user_id;

  if (investment_amount < 0) {
    return res.status(400).send({ message: "Invalid amount" });
  }

  await db.run(
    `UPDATE goals
     SET investment_amount = ?
     WHERE goal_id = ? AND user_id = ?`,
    [investment_amount, goalId, userId]
  );

  res.send({ message: "Investment updated successfully" });
});

// DELETE INVESTMENT (RESET)
app.delete("/goals/:goalId/invest", authenticateToken, async (req, res) => {
  const { goalId } = req.params;
  const userId = req.user.user_id;

  await db.run(
    `UPDATE goals
     SET investment_amount = 0
     WHERE goal_id = ? AND user_id = ?`,
    [goalId, userId]
  );

  res.send({ message: "Investment deleted successfully" });
});

// ADD INVESTMENT (INCREMENTAL)
app.put("/goals/:goalId/invest", authenticateToken, async (req, res) => {
  const { goalId } = req.params;
  const { investment_amount } = req.body;
  const userId = req.user.user_id;

  if (!investment_amount || investment_amount <= 0) {
    return res.status(400).send({ message: "Invalid investment amount" });
  }

  await db.run(
    `UPDATE goals
     SET investment_amount = COALESCE(investment_amount, 0) + ?
     WHERE goal_id = ? AND user_id = ?`,
    [investment_amount, goalId, userId]
  );

  res.send({ message: "Investment added successfully" });
});

// ================= TASKS =================
app.post("/tasks", authenticateToken, async (req, res) => {
  const { goal_id, task_name } = req.body;

  await db.run(
    "INSERT INTO tasks (goal_id, task_name) VALUES (?, ?)",
    [goal_id, task_name]
  );

  res.send({ message: "Task added successfully" });
});

app.get("/goals/:goalId/tasks", authenticateToken, async (req, res) => {
  const { goalId } = req.params;

  const tasks = await db.all(
    "SELECT * FROM tasks WHERE goal_id = ?",
    [goalId]
  );

  res.send(tasks);
});

app.put("/tasks/:taskId", authenticateToken, async (req, res) => {
  const { taskId } = req.params;
  const { task_name, status } = req.body;

  await db.run(
    `UPDATE tasks
     SET task_name=?, status=?, updated_at=CURRENT_TIMESTAMP
     WHERE task_id=?`,
    [task_name, status, taskId]
  );

  res.send({ message: "Task updated successfully" });
});

app.delete("/tasks/:taskId", authenticateToken, async (req, res) => {
  const { taskId } = req.params;

  await db.run(
    "DELETE FROM tasks WHERE task_id=?",
    [taskId]
  );

  res.send({ message: "Task deleted successfully" });
});

// ================= SUMMARY =================
app.get("/summary", authenticateToken, async (req, res) => {
  const userId = req.user.user_id;

  const incomeRow = await db.get(
    "SELECT monthly_income FROM income WHERE user_id = ?",
    [userId]
  );

  const goals = await db.all(
    "SELECT title, investment_amount FROM goals WHERE user_id = ?",
    [userId]
  );

  const totalInvestment = goals.reduce(
    (sum, g) => sum + (g.investment_amount || 0),
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
