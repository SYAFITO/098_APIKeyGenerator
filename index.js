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

// ============================
// API: LOGOUT
// ============================
app.get("/admin/logout", (req, res) => {
  req.session.destroy();
  res.json({ error: false, msg: "Logout berhasil" });
});

// ============================
// API: SAVE USER + API KEY (FIXED FOR YOUR TABLE STRUCTURE)
// ============================
app.post("/users/create", (req, res) => {
  const { first_name, last_name, email, apikey } = req.body;

  if (!first_name || !email || !apikey) {
    return res.json({ error: true, msg: "Data tidak lengkap" });
  }

  // INSERT API KEY FIRST
  const sqlKey = `
    INSERT INTO apikeys (apikey, created_at, expires_at, status)
    VALUES (?, NOW(), DATE_ADD(NOW(), INTERVAL 30 DAY), 'active')
  `;

  db.query(sqlKey, [apikey], (err, result) => {
    if (err) return res.json({ error: true, msg: err.sqlMessage });

    const apiKeyId = result.insertId;

    // INSERT USER USING FOREIGN KEY
    const sqlUser = `
      INSERT INTO users (first_name, last_name, email, api_key_id, created_at)
      VALUES (?, ?, ?, ?, NOW())
    `;

    db.query(sqlUser, [first_name, last_name, email, apiKeyId], (err2) => {
      if (err2) return res.json({ error: true, msg: err2.sqlMessage });

      return res.json({
        error: false,
        msg: "API Key dan User berhasil disimpan!"
      });
    });
  });
});

// ============================
// API: GET ALL API KEYS WITH USER DATA
// ============================
app.get("/apikeys", isLoggedIn, (req, res) => {
  const sql = `
    SELECT apikeys.*, users.first_name, users.last_name, users.email
    FROM apikeys
    LEFT JOIN users ON apikeys.id = users.api_key_id
    ORDER BY apikeys.id DESC
  `;

  db.query(sql, (err, rows) => {
    if (err) return res.json({ error: true, msg: err.sqlMessage });

    res.json({ error: false, data: rows });
  });
});

// ============================
// API: UPDATE STATUS
// ============================
app.post("/apikey/update", isLoggedIn, (req, res) => {
  const { id, status } = req.body;

  db.query(
    "UPDATE apikeys SET status = ? WHERE id = ?",
    [status, id],
    (err) => {
      if (err) return res.json({ error: true, msg: err.sqlMessage });

      res.json({ error: false, msg: "Status berhasil diperbarui" });
    }
  );
});

// ============================
// API: DELETE KEY
// ============================
app.post("/apikey/delete", isLoggedIn, (req, res) => {
  const { id } = req.body;

  db.query("DELETE FROM apikeys WHERE id = ?", [id], (err) => {
    if (err) return res.json({ error: true, msg: err.sqlMessage });

    res.json({ error: false, msg: "API Key berhasil dihapus" });
  });
});

// ============================
// START SERVER
// ============================
app.listen(3000, () => {
  console.log("\n=====================================");
  console.log(" Server running at: http://localhost:3000");
  console.log("=====================================\n");
});