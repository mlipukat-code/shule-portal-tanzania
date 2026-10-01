const express = require("express");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 3000;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));

// ===============================
// HOME
// ===============================

app.get("/", (req, res) => {
  res.send("Shule Portal Tanzania iko hewani.");
});

// ===============================
// STATUS
// ===============================

app.get("/api/status", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    res.json({
      success: true,
      message: "Backend na PostgreSQL vinafanya kazi.",
      database: "connected"
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      success: false,
      message: "Database haijaunganishwa.",
      database: "disconnected"
    });
  }
});

// ===============================
// GET SCHOOLS
// ===============================

app.get("/api/schools", async (req, res) => {
  try {

    const result = await pool.query(`
      SELECT
        id,
        name,
        region,
        district,
        school_type,
        school_type AS type,
        form_price,
        form_price AS price,
        phone,
        address,
        email,
        application_start,
        application_end,
        status,
        created_at,
        updated_at
      FROM schools
      WHERE status = 'active'
      ORDER BY id DESC
    `);

    res.json({
      success: true,
      schools: result.rows,
      count: result.rows.length
    });

  } catch (error) {

    console.error("Get schools error:", error);

    res.status(500).json({
      success: false,
      message: "Imeshindikana kupata shule.",
      schools: []
    });
  }
});

// ===============================
// SERVER
// ===============================

app.listen(PORT, () => {
  console.log(`Shule Portal Tanzania running on port ${PORT}`);
});