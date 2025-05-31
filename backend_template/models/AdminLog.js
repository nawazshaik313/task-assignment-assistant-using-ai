
const mongoose = require("mongoose");

const adminlogSchema = new mongoose.Schema({
  name: String,
  data: mongoose.Schema.Types.Mixed
});

const AdminLog = mongoose.model("AdminLog", adminlogSchema);

module.exports = { AdminLog };
