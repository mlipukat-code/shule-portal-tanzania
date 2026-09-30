const express = require("express");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static(__dirname));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.get("/api/status", (req, res) => {
  res.json({
    success: true,
    message: "Shule Portal Tanzania backend iko online"
  });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Shule Portal Tanzania running on port ${PORT}`);
});