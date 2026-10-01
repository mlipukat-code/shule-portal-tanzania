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


// ==========================================
// DATABASE SETUP
// ==========================================

async function setupDatabase() {
  try {

    await pool.query(`
      CREATE TABLE IF NOT EXISTS applications (
        id SERIAL PRIMARY KEY,

        school_id INTEGER NOT NULL
          REFERENCES schools(id),

        student_name VARCHAR(255) NOT NULL,
        gender VARCHAR(50),
        date_of_birth DATE,
        class_level VARCHAR(100),

        parent_name VARCHAR(255),
        phone VARCHAR(50),
        email VARCHAR(255),
        address TEXT,

        application_number VARCHAR(100) UNIQUE,

        status VARCHAR(30) DEFAULT 'pending',

        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);


    await pool.query(`
      CREATE TABLE IF NOT EXISTS payments (
        id SERIAL PRIMARY KEY,

        application_id INTEGER NOT NULL
          REFERENCES applications(id),

        amount NUMERIC(12,2) NOT NULL,

        payment_reference VARCHAR(150) UNIQUE,

        provider_reference VARCHAR(150),

        status VARCHAR(30) DEFAULT 'pending',

        paid_at TIMESTAMP NULL,

        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);


    console.log("Database tables ziko tayari.");

  } catch (error) {

    console.error(
      "Database setup error:",
      error
    );

  }
}


// ==========================================
// HOME
// ==========================================

app.get("/", (req, res) => {

  res.send(
    "Shule Portal Tanzania iko hewani."
  );

});


// ==========================================
// STATUS
// ==========================================

app.get("/api/status", async (req, res) => {

  try {

    await pool.query("SELECT 1");

    res.json({
      success: true,
      message:
        "Backend na PostgreSQL vinafanya kazi.",
      database: "connected"
    });

  } catch (error) {

    console.error(error);

    res.status(500).json({
      success: false,
      message:
        "Database haijaunganishwa.",
      database: "disconnected"
    });

  }

});


// ==========================================
// GET SCHOOLS
// ==========================================

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

    console.error(
      "Get schools error:",
      error
    );

    res.status(500).json({
      success: false,
      message:
        "Imeshindikana kupata shule.",
      schools: []
    });

  }

});

// ==========================================
// DATABASE TABLE CHECK
// ==========================================

app.get("/api/database-check", async (req, res) => {

  try {

    const result = await pool.query(`
      SELECT table_name
      FROM information_schema.tables
      WHERE table_schema = 'public'
        AND table_name IN ('applications', 'payments')
      ORDER BY table_name;
    `);

    res.json({
      success: true,
      tables: result.rows.map(row => row.table_name)
    });

  } catch (error) {

    console.error("Database check error:", error);

    res.status(500).json({
      success: false,
      message: "Imeshindikana kukagua database."
    });

  }

});
// ==========================================
// START SERVER
// ==========================================

async function startServer() {

  await setupDatabase();

  app.listen(PORT, () => {

    console.log(
      `Shule Portal Tanzania running on port ${PORT}`
    );

  });

}

startServer();