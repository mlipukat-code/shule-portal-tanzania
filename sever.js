const express = require("express");
const path = require("path");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname)));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false }
    : false
});

app.get("/api/status", async (req, res) => {
  try {
    await pool.query("SELECT NOW()");
    res.json({
      success: true,
      message: "Shule Portal Tanzania backend iko online"
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Database haijaunganishwa bado"
    });
  }
});

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Shule Portal Tanzania running on port ${PORT}`);
});