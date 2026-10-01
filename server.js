const express = require("express");

const app = express();

const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));

app.get("/", (req, res) => {
  res.send("Shule Portal Tanzania backend iko hewani.");
});

app.get("/api/status", (req, res) => {
  res.json({
    success: true,
    message: "Shule Portal Tanzania backend iko hewani.",
    database: "not tested yet"
  });
});

app.listen(PORT, () => {
  console.log(`Shule Portal Tanzania running on port ${PORT}`);
});