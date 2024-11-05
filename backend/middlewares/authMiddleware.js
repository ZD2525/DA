const jwt = require("jsonwebtoken")
const db = require("../models/db")
const JWT_SECRET = process.env.JWT_SECRET

// Check if user belongs to a specific group
const checkGroup = async (username, groupname) => {
  try {
    const query = "SELECT * FROM UserGroup WHERE username = ? AND user_group = ?"
    const [results] = await db.query(query, [username, groupname])
    return results.length > 0 // True if the user is in the group, false otherwise
  } catch (error) {
    console.error("Error checking group:", error)
    throw new Error("An error occurred while checking the user's group")
  }
}

// Middleware to check if the user has the 'admin' role
const requireAdmin = async (req, res, next) => {
  try {
    // Ensure `req.user` is populated by `verifyToken`
    const username = req.user.username

    // Check if the user is an admin
    const isAdmin = await checkGroup(username, "admin")

    if (!isAdmin) {
      console.log("Access forbidden: User is not an admin.")
      return res.status(403).json({ error: "Access forbidden. Admins only." })
    }

    // If user is admin, proceed
    next()
  } catch (error) {
    console.error("Error checking admin status:", error)
    res.status(500).json({ error: "Failed to verify admin status" })
  }
}

// Middleware to verify token and check user admin status
const verifyToken = (req, res, next) => {
  const token = req.cookies.token

  if (!token) {
    console.log("Access denied: No token provided.")
    return res.status(401).json({ redirect: "/login" })
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET)

    // Verify that the IP address and browser type match
    const requestIpAddress = req.ip
    const requestBrowserType = req.headers["user-agent"]

    if (decoded.ipAddress !== requestIpAddress || decoded.browserType !== requestBrowserType) {
      console.log("Access denied: IP address or browser type mismatch.")
      return res.status(401).json({ redirect: "/login" })
    }

    req.user = decoded
    next()
  } catch (err) {
    console.error("Token verification failed:", err)
    return res.status(401).json({ redirect: "/login" })
  }
}

module.exports = { verifyToken, checkGroup, requireAdmin }
