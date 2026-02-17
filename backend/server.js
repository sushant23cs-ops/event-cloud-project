require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const db = require("./db");
const { auth, adminOnly } = require("./middleware/auth");

const app = express();
app.use(cors());
app.use(express.json());

app.get("/", (req, res) => res.json({ ok: true, message: "API running" }));

// ---------- AUTH ----------
app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ message: "Missing fields" });

    const [exists] = await db.query("SELECT id FROM users WHERE email=?", [email]);
    if (exists.length) return res.status(409).json({ message: "Email already registered" });

    const password_hash = await bcrypt.hash(password, 10);

    // first user becomes ADMIN (demo-friendly)
    const [countRows] = await db.query("SELECT COUNT(*) AS c FROM users");
    const role = countRows[0].c === 0 ? "ADMIN" : "USER";

    const [result] = await db.query(
      "INSERT INTO users (name, email, password_hash, role) VALUES (?,?,?,?)",
      [name, email, password_hash, role]
    );

    return res.json({ message: "Registered", userId: result.insertId, role });
  } catch (e) {
    return res.status(500).json({ message: "Server error" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: "Missing fields" });

    const [rows] = await db.query("SELECT * FROM users WHERE email=?", [email]);
    if (!rows.length) return res.status(401).json({ message: "Invalid credentials" });

    const user = rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ message: "Invalid credentials" });

    const token = jwt.sign(
      { id: user.id, role: user.role, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    return res.json({
      token,
      user: { id: user.id, name: user.name, email: user.email, role: user.role },
    });
  } catch (e) {
    return res.status(500).json({ message: "Server error" });
  }
});

// ---------- EVENTS ----------
app.get("/api/events", async (req, res) => {
  const [rows] = await db.query("SELECT * FROM events ORDER BY event_date ASC");
  res.json(rows);
});

// Admin create event (includes category)
app.post("/api/events", auth, adminOnly, async (req, res) => {
  const { title, event_date, location, capacity, category } = req.body;
  if (!title || !event_date || !location) return res.status(400).json({ message: "Missing fields" });

  const cap = Number(capacity || 50);
  const cat = (category || "General").trim();

  const [result] = await db.query(
    "INSERT INTO events (title, event_date, location, capacity, category, created_by) VALUES (?,?,?,?,?,?)",
    [title, event_date, location, cap, cat, req.user.id]
  );

  res.json({ message: "Event created", id: result.insertId });
});

app.delete("/api/events/:id", auth, adminOnly, async (req, res) => {
  await db.query("DELETE FROM events WHERE id=?", [req.params.id]);
  res.json({ message: "Event deleted" });
});

// ---------- REGISTRATIONS ----------
app.post("/api/registrations/:eventId", auth, async (req, res) => {
  const eventId = Number(req.params.eventId);

  const [[event]] = await db.query("SELECT capacity FROM events WHERE id=?", [eventId]);
  if (!event) return res.status(404).json({ message: "Event not found" });

  const [[count]] = await db.query(
    "SELECT COUNT(*) AS c FROM registrations WHERE event_id=? AND status='REGISTERED'",
    [eventId]
  );
  if (count.c >= event.capacity) return res.status(400).json({ message: "Event full" });

  try {
    await db.query(
      "INSERT INTO registrations (user_id, event_id, status) VALUES (?,?, 'REGISTERED')",
      [req.user.id, eventId]
    );
  } catch {
    await db.query(
      "UPDATE registrations SET status='REGISTERED' WHERE user_id=? AND event_id=?",
      [req.user.id, eventId]
    );
  }

  res.json({ message: "Registered" });
});

app.get("/api/me/registrations", auth, async (req, res) => {
  const [rows] = await db.query(
    `SELECT r.id as reg_id, r.status, e.*
     FROM registrations r
     JOIN events e ON e.id = r.event_id
     WHERE r.user_id=?
     ORDER BY e.event_date ASC`,
    [req.user.id]
  );
  res.json(rows);
});

app.post("/api/me/cancel/:eventId", auth, async (req, res) => {
  const eventId = Number(req.params.eventId);
  await db.query(
    "UPDATE registrations SET status='CANCELLED' WHERE user_id=? AND event_id=?",
    [req.user.id, eventId]
  );
  res.json({ message: "Cancelled" });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log("Server running on", PORT));
