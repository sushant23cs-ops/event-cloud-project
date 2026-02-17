require("dotenv").config();

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const pool = require("./db");
const { auth, adminOnly } = require("./middleware/auth");

const app = express();

app.use(cors());
app.use(express.json());

// ---------- Root & Health ----------
app.get("/", (req, res) => res.json({ ok: true, message: "API running" }));
app.get("/health", (req, res) => res.json({ ok: true }));

// ---------- Register ----------
app.post("/api/register", async (req, res) => {
  try {
    const { name, email, password } = req.body || {};
    if (!name || !email || !password) {
      return res.status(400).json({ error: "Missing fields" });
    }

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

    res.json({ ok: true, message: "Registered" });
  } catch (err) {
    console.error("POST /api/register:", err);
    res.status(500).json({ error: err.code || err.message });
  }
});

// ---------- Login ----------
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ error: "Missing fields" });
    }

    const [rows] = await pool.query("SELECT * FROM users WHERE email = ?", [
      email,
    ]);

    if (!rows.length) return res.status(401).json({ error: "Invalid login" });

    const user = rows[0];
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: "Invalid login" });

    if (!process.env.JWT_SECRET) {
      return res.status(500).json({ error: "JWT_SECRET missing on server" });
    }

    const token = jwt.sign(
      { id: user.id, role: user.role, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({
      ok: true,
      token,
      user: { id: user.id, role: user.role, email: user.email, name: user.name },
    });
  } catch (err) {
    console.error("POST /api/login:", err);
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
    console.error("GET /api/events:", err);
    res.status(500).json({ error: err.code || err.message });
  }
});

// ---------- Create Event (Admin) ----------
app.post("/api/events", auth, adminOnly, async (req, res) => {
  try {
    const { title, category, location, event_date, description } = req.body || {};
    if (!title || !category || !location || !event_date) {
      return res.status(400).json({ error: "Missing fields" });
    }

    await pool.query(
      "INSERT INTO events (title, category, location, event_date, description) VALUES (?, ?, ?, ?, ?)",
      [title, category, location, event_date, description || ""]
    );

    res.json({ ok: true, message: "Event created" });
  } catch (err) {
    console.error("POST /api/events:", err);
    res.status(500).json({ error: err.code || err.message });
  }
});

// ---------- Register for Event ----------
app.post("/api/register-event", auth, async (req, res) => {
  try {
    const { event_id } = req.body || {};
    if (!event_id) return res.status(400).json({ error: "event_id required" });

    // prevent duplicates
    const [existing] = await pool.query(
      "SELECT id FROM registrations WHERE user_id = ? AND event_id = ?",
      [req.user.id, event_id]
    );
    if (existing.length) return res.status(409).json({ error: "Already registered" });

    await pool.query(
      "INSERT INTO registrations (user_id, event_id) VALUES (?, ?)",
      [req.user.id, event_id]
    );

    res.json({ ok: true, message: "Registered for event" });
  } catch (err) {
    console.error("POST /api/register-event:", err);
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
       WHERE r.user_id = ?
       ORDER BY e.event_date ASC`,
      [req.user.id]
    );

    res.json(rows);
  } catch (err) {
    console.error("GET /api/my-registrations:", err);
    res.status(500).json({ error: err.code || err.message });
  }
});

// ---------- Crash Protection ----------
process.on("unhandledRejection", (reason) => console.error("Unhandled Rejection:", reason));
process.on("uncaughtException", (err) => console.error("Uncaught Exception:", err));

// ---------- Start ----------
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log("Server running on", PORT));
