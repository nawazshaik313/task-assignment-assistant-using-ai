
const express = require("express");
const router = express.Router();
const { CurrentUser } = require("../models/CurrentUser");

// GET all
router.get("/", async (req, res) => {
  try {
    const data = await CurrentUser.find();
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST (replace all)
router.post("/", async (req, res) => {
  try {
    await CurrentUser.deleteMany({});
    await CurrentUser.insertMany(req.body);
    res.json({ message: "CurrentUsers saved successfully" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
