const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
require("dotenv").config();

const app = express();
app.use(cors());
app.use(express.json());

// Import routes once only
const taskRoutes = require("./routes/taskRoutes");
const userRoutes = require("./routes/userRoutes");
const assignmentRoutes = require("./routes/assignmentRoutes");
const pendingUserRoutes = require("./routes/pendingUserRoutes");
const programRoutes = require("./routes/programRoutes");
const adminLogRoutes = require("./routes/adminLogRoutes");
const currentUserRoutes = require("./routes/currentUserRoutes");

// Use routes
app.use("/api/tasks", taskRoutes);
app.use("/api/users", userRoutes);
app.use("/api/assignments", assignmentRoutes);
app.use("/api/pending-users", pendingUserRoutes);
app.use("/api/programs", programRoutes);
app.use("/api/admin-logs", adminLogRoutes);
app.use("/api/current-user", currentUserRoutes);

// Connect MongoDB
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB connected"))
  .catch(err => console.log(err));

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
