const express = require("express");
const path = require("path");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 3000;

/*
  PostgreSQL connection
  DATABASE_URL inatoka Railway Variables
*/
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));


// Homepage
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});


// Database status
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


// Start server
app.listen(PORT, "0.0.0.0", () => {
  console.log(
    `Shule Portal Tanzania running on port ${PORT}`
  );
});