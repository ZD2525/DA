const express = require("express")
const router = express.Router()
const userController = require("../controllers/userController")
const { verifyToken, requireAdmin } = require("../middlewares/authMiddleware")

// Public Routes
router.post("/login", userController.loginUser)
router.post("/logout", userController.logoutUser)

// Apply verifyToken for all routes that follow
router.use(verifyToken)

// Profile management for authenticated users
router
  .route("/editprofile")
  .get(userController.getProfile) // Get profile
  .put(userController.updateProfile) // Update profile

// Apply requireAdmin for all admin routes that follow
router.use(requireAdmin)

// Admin-Protected Routes
router
  .route("/usermanagement")
  .get(userController.getUserManagement) // List all users
  .post(userController.createUser) // Create a new user
router.get("/groups", userController.getGroups) // Get all groups
router.post("/create-group", userController.createGroup) // Create a new group
router.post("/get-user", userController.getUserByUsername) // Retrieve user by username
router.put("/update-user", userController.editUser) // Update user details
router.delete("/remove-user-group", userController.removeUserGroup) // Remove user from group

module.exports = router
