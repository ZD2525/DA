import React, { useState, useEffect, useCallback } from "react"
import { Route, Routes, Navigate, useLocation, useNavigate } from "react-router-dom"
import axios from "axios"
import TaskManagementSystem from "./components/TaskManagement"
import UserManagementSystem from "./components/UserManagement"
import Login from "./components/Login"
import Header from "./components/Header"
import EditProfile from "./components/EditProfile"
import NotFound from "./components/NotFound"

axios.defaults.withCredentials = true

const App = () => {
  const [username, setUsername] = useState("")
  const [isAdmin, setIsAdmin] = useState(false)
  const [isAuthenticated, setIsAuthenticated] = useState(false)
  const [isLoading, setIsLoading] = useState(true)
  const location = useLocation()
  const navigate = useNavigate()

  // Fetch profile and update both username and isAdmin status
  const fetchUserProfile = useCallback(async () => {
    try {
      const response = await axios.get("http://localhost:3000/editprofile")
      setUsername(response.data.username)
      setIsAdmin(response.data.isAdmin)
      setIsAuthenticated(true)
      return response.data // Return the profile data
    } catch (err) {
      console.warn("Failed to fetch user profile. Redirecting to login.")
      setIsAuthenticated(false)
      setIsAdmin(false)
      setUsername("")
      navigate("/login")
      return null
    }
  }, [navigate])

  // Run profile fetch to check authentication on page load or navigation
  useEffect(() => {
    if (location.pathname !== "/login") {
      fetchUserProfile().then(() => setIsLoading(false))
    } else {
      setIsLoading(false)
    }
  }, [location.pathname, fetchUserProfile])

  // Log out and clear states
  const handleLogout = useCallback(async () => {
    try {
      await axios.post("http://localhost:3000/logout")
      setIsAuthenticated(false)
      setIsAdmin(false)
      setUsername("")
      navigate("/login")
    } catch (error) {
      console.error("Logout failed:", error)
    }
  }, [navigate])

  if (isLoading) {
    return <div>Loading...</div>
  }

  return (
    <>
      {isAuthenticated && <Header username={username} isAdmin={isAdmin} handleLogout={handleLogout} />}
      <div className="main-content">
        <Routes>
          <Route path="/" element={isAuthenticated ? <Navigate to="/taskmanagementsystem" /> : <Navigate to="/login" />} />
          <Route path="/login" element={isAuthenticated ? <Navigate to="/taskmanagementsystem" /> : <Login fetchUserProfile={fetchUserProfile} />} />
          <Route path="/taskmanagementsystem" element={<TaskManagementSystem username={username} />} />
          <Route path="/usermanagement" element={isAuthenticated && isAdmin ? <UserManagementSystem fetchUserProfile={fetchUserProfile} username={username} isAdmin={isAdmin} handleLogout={handleLogout} /> : <Navigate to={isAuthenticated ? "/taskmanagementsystem" : "/login"} />} />
          <Route path="/editprofile" element={<EditProfile username={username} />} />
          <Route path="*" element={<NotFound />} />
        </Routes>
      </div>
    </>
  )
}

export default App
