const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcryptjs");
const path = require("path");
const session = require("express-session");
const app = express();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

app.use(
  session({
    secret: "supersecretkey",
    resave: false,
    saveUninitialized: true,
  })
);

// ============================
// DATABASE CONNECTION
// ============================
const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "Bismillah123",
  database: "update_db",
  port: 3307,
});

db.connect((err) => {
  if (err) throw err;
  console.log("MySQL Connected!");
});

// ============================
// MIDDLEWARE LOGIN PROTECT
// ============================
function isLoggedIn(req, res, next) {
  if (!req.session.admin) {
    return res.status(401).json({ error: true, msg: "Belum login" });
  }
  next();
}

// ============================
// API: LOGIN ADMIN
// ============================
app.post("/admin/login", (req, res) => {
  const { email, password } = req.body;

  db.query("SELECT * FROM admins WHERE email = ?", [email], async (err, rows) => {
    if (err) return res.json({ error: true, msg: err.sqlMessage });

    if (rows.length === 0)
      return res.json({ error: true, msg: "Admin tidak ditemukan" });

    const admin = rows[0];
    const match = await bcrypt.compare(password, admin.password);

    if (!match) return res.json({ error: true, msg: "Password salah" });

    req.session.admin = admin;
    res.json({ error: false, msg: "Login sukses!" });
  });
});

