const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const pool = require("./db");
const auth = require("./middleware/auth");

const app = express();

// ---------- Middleware ----------
app.use(cors());
app.use(express.json());

// ---------- Helpers ----------
const signToken = (user) => {
  return jwt.sign(
    { id: user.id, email: user.email, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );
};

// ---------- Safe Health Routes ----------
app.get("/", (req, res) => res.json({ ok: true, message: "API running" }));
app.get("/health", (req, res) => res.json({ ok: true }));

// ---------- Auth Routes ----------
app.post("/api/register", async (req, res) => {
  try {
    const { name, email, password } = req.body || {};
    if (!name || !email || !password) {
      return res.status(400).json({ error: "Missing fields" });
    }

    const [existing] = await pool.query("SELECT id FROM users WHERE email = ?", [
      email,
    ]);
    if (existing.length) {
      return res.status(409).json({ error: "Email already registered" });
    }

    const password_hash = await bcrypt.hash(password, 10);

    await pool.query(
      "INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, 'user')",
      [name, email, password_hash]
    );

    return res.json({ ok: true, message: "Registered successfully" });
  } catch (err) {
    console.error("POST /api/register error:", err);
    return res
      .status(500)
      .json({ error: "Server error", code: err.code || err.message });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ error: "Missing fields" });
    }

    const [rows] = await pool.query(
      "SELECT id, name, email, password_hash, role FROM users WHERE email = ?",
      [email]
    );

    if (!rows.length) return res.status(401).json({ error: "Invalid login" });

    const user = rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: "Invalid login" });

    const token = signToken(user);

    return res.json({
      ok: true,
      token,
      user: { id: user.id, name: user.name, email: user.email, role: user.role },
    });
  } catch (err) {
    console.error("POST /api/login error:", err);
    return res
      .status(500)
      .json({ error: "Server error", code: err.code || err.message });
  }
});

// ---------- Events ----------
app.get("/api/events", async (req, res) => {
  try {
    const [rows] = await pool.query(
      "SELECT * FROM events ORDER BY event_date ASC"
    );
    return res.json(rows);
  } catch (err) {
    console.error("GET /api/events error:", err);
    // IMPORTANT: don't crash the server
    return res
      .status(500)
      .json({ error: "DB error", code: err.code || err.message });
  }
});

// Create event (admin only)
app.post("/api/events", auth, async (req, res) => {
  try {
    if (req.user.role !== "admin") {
      return res.status(403).json({ error: "Admin only" });
    }

    const { title, category, location, event_date, description } = req.body || {};
    if (!title || !category || !location || !event_date) {
      return res.status(400).json({ error: "Missing fields" });
    }

    await pool.query(
      `INSERT INTO events (title, category, location, event_date, description)
       VALUES (?, ?, ?, ?, ?)`,
      [title, category, location, event_date, description || ""]
    );

    return res.json({ ok: true, message: "Event created" });
  } catch (err) {
    console.error("POST /api/events error:", err);
    return res
      .status(500)
      .json({ error: "Server error", code: err.code || err.message });
  }
});

// ---------- Categories ----------
app.get("/api/categories", async (req, res) => {
  try {
    const [rows] = await pool.query(
      "SELECT DISTINCT category FROM events ORDER BY category ASC"
    );
    return res.json(rows.map((r) => r.category));
  } catch (err) {
    console.error("GET /api/categories error:", err);
    return res
      .status(500)
      .json({ error: "DB error", code: err.code || err.message });
  }
});

// ---------- Search ----------
app.get("/api/search", async (req, res) => {
  try {
    const q = (req.query.q || "").trim();
    const category = (req.query.category || "").trim();

    let sql = "SELECT * FROM events WHERE 1=1";
    const params = [];

    if (q) {
      sql += " AND (title LIKE ? OR location LIKE ? OR description LIKE ?)";
      params.push(`%${q}%`, `%${q}%`, `%${q}%`);
    }

    if (category) {
      sql += " AND category = ?";
      params.push(category);
    }

    sql += " ORDER BY event_date ASC";

    const [rows] = await pool.query(sql, params);
    return res.json(rows);
  } catch (err) {
    console.error("GET /api/search error:", err);
    return res
      .status(500)
      .json({ error: "DB error", code: err.code || err.message });
  }
});

// ---------- Registrations ----------
app.post("/api/register-event", auth, async (req, res) => {
  try {
    const { event_id } = req.body || {};
    if (!event_id) return res.status(400).json({ error: "event_id required" });

    // prevent duplicate registrations
    const [existing] = await pool.query(
      "SELECT id FROM registrations WHERE user_id = ? AND event_id = ?",
      [req.user.id, event_id]
    );
    if (existing.length) {
      return res.status(409).json({ error: "Already registered" });
    }

    await pool.query(
      "INSERT INTO registrations (user_id, event_id) VALUES (?, ?)",
      [req.user.id, event_id]
    );

    return res.json({ ok: true, message: "Registered for event" });
  } catch (err) {
    console.error("POST /api/register-event error:", err);
    return res
      .status(500)
      .json({ error: "Server error", code: err.code || err.message });
  }
});

app.get("/api/my-registrations", auth, async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT r.id as registration_id, e.*
       FROM registrations r
       JOIN events e ON e.id = r.event_id
       WHERE r.user_id = ?
       ORDER BY e.event_date ASC`,
      [req.user.id]
    );
    return res.json(rows);
  } catch (err) {
    console.error("GET /api/my-registrations error:", err);
    return res
      .status(500)
      .json({ error: "DB error", code: err.code || err.message });
  }
});

// ---------- Global Crash Protection ----------
process.on("unhandledRejection", (reason) => {
  console.error("Unhandled Rejection:", reason);
});
process.on("uncaughtException", (err) => {
  console.error("Uncaught Exception:", err);
});

// ---------- Start ----------
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log("Server running on", PORT));
