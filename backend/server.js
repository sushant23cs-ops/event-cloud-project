const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const pool = require("./db");
const { auth, adminOnly } = require("./middleware/auth"); // 🔥 FIXED IMPORT

const app = express();

app.use(cors());
app.use(express.json());

// ---------- Root & Health ----------
app.get("/", (req, res) => {
  res.json({ ok: true, message: "API running" });
});

app.get("/health", (req, res) => {
  res.json({ ok: true });
});

// ---------- Register ----------
app.post("/api/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    const [existing] = await pool.query(
      "SELECT id FROM users WHERE email = ?",
      [email]
    );

    if (existing.length) {
      return res.status(409).json({ error: "Email already exists" });
    }

    const hash = await bcrypt.hash(password, 10);

    await pool.query(
      "INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, 'user')",
      [name, email, hash]
    );

    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.code || err.message });
  }
});

// ---------- Login ----------
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const [rows] = await pool.query(
      "SELECT * FROM users WHERE email = ?",
      [email]
    );

    if (!rows.length) {
      return res.status(401).json({ error: "Invalid login" });
    }

    const user = rows[0];
    const valid = await bcrypt.compare(password, user.password_hash);

    if (!valid) {
      return res.status(401).json({ error: "Invalid login" });
    }

    const token = jwt.sign(
      { id: user.id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({ token, user: { id: user.id, role: user.role } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.code || err.message });
  }
});

// ---------- Get Events ----------
app.get("/api/events", async (req, res) => {
  try {
    const [rows] = await pool.query(
      "SELECT * FROM events ORDER BY event_date ASC"
    );
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.code || err.message });
  }
});

// ---------- Create Event (Admin) ----------
app.post("/api/events", auth, adminOnly, async (req, res) => {
  try {
    const { title, category, location, event_date, description } = req.body;

    await pool.query(
      "INSERT INTO events (title, category, location, event_date, description) VALUES (?, ?, ?, ?, ?)",
      [title, category, location, event_date, description]
    );

    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.code || err.message });
  }
});

// ---------- Register for Event ----------
app.post("/api/register-event", auth, async (req, res) => {
  try {
    const { event_id } = req.body;

    await pool.query(
      "INSERT INTO registrations (user_id, event_id) VALUES (?, ?)",
      [req.user.id, event_id]
    );

    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.code || err.message });
  }
});

// ---------- My Registrations ----------
app.get("/api/my-registrations", auth, async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT e.*
       FROM registrations r
       JOIN events e ON r.event_id = e.id
       WHERE r.user_id = ?`,
      [req.user.id]
    );

    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.code || err.message });
  }
});

// ---------- Crash Protection ----------
process.on("unhandledRejection", (reason) => {
  console.error("Unhandled Rejection:", reason);
});

process.on("uncaughtException", (err) => {
  console.error("Uncaught Exception:", err);
});

// ---------- Start ----------
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log("Server running on", PORT));
