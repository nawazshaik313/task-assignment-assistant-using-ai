
const mongoose = require("mongoose");

const pendinguserSchema = new mongoose.Schema({
  name: String,
  data: mongoose.Schema.Types.Mixed
});

const PendingUser = mongoose.model("PendingUser", pendinguserSchema);

module.exports = { PendingUser };
