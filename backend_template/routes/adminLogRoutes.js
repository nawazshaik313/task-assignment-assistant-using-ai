
const express = require("express");
const router = express.Router();
const AdminLog = require("../models/AdminLog");

router.get("/", async (req, res) => {
  const logs = await AdminLog.find();
  res.json(logs);
});

router.post("/", async (req, res) => {
  try {
    await AdminLog.deleteMany({});
    await AdminLog.insertMany(req.body);
    res.json({ message: "Admin logs saved successfully" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
