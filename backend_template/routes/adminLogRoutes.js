
const express = require("express");
const router = express.Router();
const { AdminLog } = require("../models/AdminLog");

// GET all
router.get("/", async (req, res) => {
  try {
    const data = await AdminLog.find();
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST (replace all)
router.post("/", async (req, res) => {
  try {
    await AdminLog.deleteMany({});
    await AdminLog.insertMany(req.body);
    res.json({ message: "AdminLogs saved successfully" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
