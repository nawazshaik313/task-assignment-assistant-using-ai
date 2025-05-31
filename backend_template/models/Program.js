
const mongoose = require("mongoose");

const programSchema = new mongoose.Schema({
  name: String,
  data: mongoose.Schema.Types.Mixed
});

const Program = mongoose.model("Program", programSchema);

module.exports = { Program };
