
const express = require("express");
const router = express.Router();
const { Assignment } = require("../models/Assignment");

// GET all
router.get("/", async (req, res) => {
  try {
    const data = await Assignment.find();
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST (replace all)
router.post("/", async (req, res) => {
  try {
    await Assignment.deleteMany({});
    await Assignment.insertMany(req.body);
    res.json({ message: "Assignments saved successfully" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
