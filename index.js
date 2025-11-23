const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcryptjs");
const path = require("path");
const session = require("express-session");
const app = express();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
// Menyediakan file statis (seperti admin.html dan index.html) dari folder 'public'
app.use(express.static(path.join(__dirname, "public"))); 

app.use(
  session({
    secret: "supersecretkey", // Ganti dengan secret key yang kuat
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
  // Pastikan database 'activity_db' sudah ada dan berisi tabel yang benar
  database: "activity_db", 
  port: 3307,
});

db.connect((err) => {
  if (err) {
      console.error("Error koneksi MySQL:", err.message);
      console.error("Pastikan MySQL Server (Port 3307) berjalan.");
      return; // Hentikan proses jika koneksi database gagal
    }
  console.log("MySQL Connected!");
});

// ============================
// MIDDLEWARE LOGIN PROTECT
// ============================
function isLoggedIn(req, res, next) {
  if (!req.session.admin) {
    // Menggunakan status 401 Unauthorized jika sesi admin tidak ada
    return res.status(401).json({ error: true, msg: "Belum login" });
  }
  next();
}

// ============================
// API: REGISTER ADMIN
// ============================
app.post("/admin/register", async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: true, msg: "Email dan password wajib diisi." });
    }
    
    try {
        // Cek apakah admin sudah terdaftar
        const [rows] = await db.promise().query("SELECT id FROM admins WHERE email = ?", [email]);

        if (rows.length > 0) {
            return res.status(409).json({ error: true, msg: "Email sudah terdaftar sebagai admin." });
        }
        
        // Hash password sebelum disimpan
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Simpan admin baru
        const sql = "INSERT INTO admins (email, password, created_at) VALUES (?, ?, NOW())";

        const [result] = await db.promise().query(sql, [email, hashedPassword]);

        res.status(201).json({
            error: false,
            msg: "Registrasi admin berhasil!",
            adminId: result.insertId,
        });

    } catch (err) {
        console.error("Error Register Admin:", err.message);
        res.status(500).json({ error: true, msg: "Gagal Registrasi/SQL Error: " + (err.sqlMessage || err.message) });
    }
});

// ============================
// API: LOGIN ADMIN
// ============================
app.post("/admin/login", async (req, res) => {
  const { email, password } = req.body;

    try {
        const [rows] = await db.promise().query("SELECT * FROM admins WHERE email = ?", [email]);
        
        // Admin tidak ditemukan
        if (rows.length === 0)
          return res.status(401).json({ error: true, msg: "Admin tidak ditemukan" });

        const admin = rows[0];
        
        // Bandingkan password
        const match = await bcrypt.compare(password, admin.password); 

        if (!match) return res.status(401).json({ error: true, msg: "Password salah" });

        req.session.admin = admin;
        res.json({ error: false, msg: "Login sukses!" });

    } catch (err) {
        console.error("Error Login Admin:", err.message);
        res.status(500).json({ error: true, msg: "Gagal Login/SQL Error: " + (err.sqlMessage || err.message) });
    }
});

// ============================
// API: LOGOUT
// ============================
app.get("/admin/logout", (req, res) => {
  req.session.destroy();
  res.json({ error: false, msg: "Logout berhasil" });
});

// ============================
// API: SAVE USER + API KEY (KODE TERKOREKSI)
// ============================
app.post("/users/create", async (req, res) => {
  const { first_name, last_name, email, apikey } = req.body;

  if (!first_name || !email || !apikey) {
    return res.status(400).json({ error: true, msg: "Data tidak lengkap" });
  }

    try {
        // INSERT API KEY FIRST

        const sqlKey = "INSERT INTO apikeys (apikey, created_at, expires_at, status) VALUES (?, NOW(), DATE_ADD(NOW(), INTERVAL 30 DAY), 'active')";
        
        const [resultKey] = await db.promise().query(sqlKey, [apikey]);

        const apiKeyId = resultKey.insertId;

        // INSERT USER USING FOREIGN KEY
 
        const sqlUser = "INSERT INTO users (first_name, last_name, email, api_key_id, created_at) VALUES (?, ?, ?, ?, NOW())";
        
        await db.promise().query(sqlUser, [first_name, last_name, email, apiKeyId]);

        return res.json({
            error: false,
            msg: "API Key dan User berhasil disimpan!"
        });
        
    } catch (err) {
        console.error("Error Save User/API Key:", err.message);
        return res.status(500).json({ error: true, msg: "SQL Error saat menyimpan data: " + (err.sqlMessage || err.message) });
    }
});

// ============================
// API: GET ALL API KEYS WITH USER DATA
// ============================
app.get("/apikeys", isLoggedIn, (req, res) => {
  const sql = `
    SELECT apikeys.*, users.first_name, users.last_name, users.email AS user_email
    FROM apikeys
    LEFT JOIN users ON apikeys.id = users.api_key_id
    ORDER BY apikeys.id DESC
  `;

  db.query(sql, (err, rows) => {
    if (err) {
        console.error("SQL Error di /apikeys:", err.message);
        // Mengirim error yang spesifik jika terjadi masalah sintaks pada query ini
        return res.status(500).json({ error: true, msg: "SQL Error di /apikeys: " + err.sqlMessage });
    }

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
      if (err) return res.status(500).json({ error: true, msg: err.sqlMessage });

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
    if (err) {
        if (err.code === 'ER_ROW_IS_REFERENCED_2') {
             // Tangani error jika data masih terikat Foreign Key
             return res.status(400).json({ error: true, msg: "Gagal hapus: API Key masih digunakan oleh user. Hapus user terkait dahulu." });
        }
        return res.status(500).json({ error: true, msg: err.sqlMessage });
    }

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