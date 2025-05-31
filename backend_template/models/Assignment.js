
const mongoose = require("mongoose");

const assignmentSchema = new mongoose.Schema({
  name: String,
  data: mongoose.Schema.Types.Mixed
});

const Assignment = mongoose.model("Assignment", assignmentSchema);

module.exports = { Assignment };
