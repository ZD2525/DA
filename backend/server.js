require("dotenv").config()
const express = require("express")
const userRoutes = require("./routes/userRoutes")
const cors = require("cors")
const cookieParser = require("cookie-parser")

const app = express()
const PORT = process.env.PORT || 3000

// Middleware
app.use(cookieParser()) // Parses cookies from the client
app.use(
  cors({
    origin: "http://localhost:5000", // Allow requests only from the frontend's origin
    credentials: true // Allow cookies to be sent with requests
  })
)
app.use(express.json())

// Routes
app.use("/", userRoutes)

// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`)
})
