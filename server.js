const express = require("express");
const path = require("path");
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


// ================================
// DATABASE INITIALIZATION
// ================================

async function initializeDatabase() {

  try {

    await pool.query(`
      CREATE TABLE IF NOT EXISTS schools (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        region VARCHAR(100) NOT NULL,
        district VARCHAR(100) NOT NULL,
        school_type VARCHAR(100) NOT NULL,
        form_price NUMERIC(12,2) NOT NULL DEFAULT 0,
        phone VARCHAR(30),
        address TEXT,
        email VARCHAR(255),
        application_start DATE,
        application_end DATE,
        status VARCHAR(30) NOT NULL DEFAULT 'active',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    console.log("Schools table iko tayari.");

  } catch (error) {

    console.error(
      "Database initialization error:",
      error
    );

  }
}


// ================================
// HOME
// ================================

app.get("/", (req, res) => {

  res.sendFile(
    path.join(__dirname, "index.html")
  );

});


// ================================
// DATABASE STATUS
// ================================

app.get("/api/status", async (req, res) => {

  try {

    const result =
      await pool.query("SELECT NOW()");

    res.json({

      success: true,

      message:
        "Shule Portal Tanzania backend na PostgreSQL vimeunganishwa",

      database:
        "connected",

      time:
        result.rows[0].now

    });

  } catch (error) {

    console.error(
      "Database error:",
      error
    );

    res.status(500).json({

      success: false,

      message:
        "Database connection failed"

    });

  }

});


// ================================
// START SERVER
// ================================

async function startServer() {

  await initializeDatabase();

  app.listen(
    PORT,
    "0.0.0.0",
    () => {

      console.log(
        `Shule Portal Tanzania running on port ${PORT}`
      );

    }
  );

}

startServer();