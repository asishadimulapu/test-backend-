require('dotenv').config(); // Load environment variables from .env file (for local development)

const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const cors = require("cors");
const morgan = require("morgan")
const eventRoutes = require("./app_api/routes/eventRoutes");
const userRoutes = require("./app_api/routes/userRoutes"); // Import user routes

const app = express();
const PORT = process.env.PORT;
const MONGO_URI = process.env.MONGO; // MongoDB URI from environment variables

// Middleware
app.use(cors());
app.use(morgan("dev"))
app.use(bodyParser.json()); // Parse incoming JSON requests

// Connect to MongoDB
mongoose.connect(MONGO_URI)
    .then(() => {
        console.log("Connected to MongoDB!");
    })
    .catch((error) => {
        console.error("Error connecting to MongoDB:", error);
    });

// Define API routes
app.use("/api", eventRoutes);
app.use("/api/users", userRoutes); // User routes mounted under "/api/users"

// Start server
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
