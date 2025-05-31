
const mongoose = require("mongoose");

const currentuserSchema = new mongoose.Schema({
  name: String,
  data: mongoose.Schema.Types.Mixed
});

const CurrentUser = mongoose.model("CurrentUser", currentuserSchema);

module.exports = { CurrentUser };
