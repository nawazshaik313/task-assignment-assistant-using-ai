
const express = require("express");
const router = express.Router();
const { PendingUser } = require("../models/PendingUser");

// GET all
router.get("/", async (req, res) => {
  try {
    const data = await PendingUser.find();
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST (replace all)
router.post("/", async (req, res) => {
  try {
    await PendingUser.deleteMany({});
    await PendingUser.insertMany(req.body);
    res.json({ message: "PendingUsers saved successfully" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
