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
    console.error("Database initialization error:", error);
  }
}


// ================================
// HOME
// ================================

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});


// ================================
// DATABASE STATUS
// ================================

app.get("/api/status", async (req, res) => {

  try {

    const result = await pool.query("SELECT NOW()");

    res.json({
      success: true,
      message: "Shule Portal Tanzania backend na PostgreSQL vimeunganishwa",
      database: "connected",
      time: result.rows[0].now
    });

  } catch (error) {

    console.error("Database error:", error);

    res.status(500).json({
      success: false,
      message: "Database connection failed"
    });

  }

});


// ================================
// GET ALL SCHOOLS
// ================================

app.get("/api/schools", async (req, res) => {

  try {

    const result = await pool.query(`
      SELECT *
      FROM schools
      ORDER BY id DESC
    `);

    res.json({
      success: true,
      schools: result.rows
    });

  } catch (error) {

    console.error("Get schools error:", error);

    res.status(500).json({
      success: false,
      message: "Imeshindikana kupata taarifa za shule."
    });

  }

});


// ================================
// ADD SCHOOL
// ================================

app.post("/api/schools", async (req, res) => {

  try {

    const {
      name,
      region,
      district,
      school_type,
      form_price,
      phone,
      address,
      email,
      application_start,
      application_end
    } = req.body;


    if (
      !name ||
      !region ||
      !district ||
      !school_type ||
      form_price === undefined
    ) {

      return res.status(400).json({
        success: false,
        message: "Tafadhali jaza taarifa muhimu za shule."
      });

    }


    const result = await pool.query(
      `
      INSERT INTO schools
      (
        name,
        region,
        district,
        school_type,
        form_price,
        phone,
        address,
        email,
        application_start,
        application_end
      )
      VALUES
      ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
      RETURNING *
      `,
      [
        name,
        region,
        district,
        school_type,
        form_price,
        phone || null,
        address || null,
        email || null,
        application_start || null,
        application_end || null
      ]
    );


    res.status(201).json({
      success: true,
      message: "Shule imeongezwa kwa mafanikio.",
      school: result.rows[0]
    });

  } catch (error) {

    console.error("Add school error:", error);

    res.status(500).json({
      success: false,
      message: "Imeshindikana kuongeza shule."
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