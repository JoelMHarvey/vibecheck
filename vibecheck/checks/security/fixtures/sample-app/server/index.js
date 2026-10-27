const express = require("express");
const cors = require("cors");
const app = express();
app.use(cors());

app.get("/user/:id", async (req, res) => {
  const rows = await pool.query(`SELECT * FROM users WHERE id = ${req.params.id}`);
  res.json(rows);
});

app.post("/calc", (req, res) => {
  res.json({ answer: eval(req.body.expression) });
});
