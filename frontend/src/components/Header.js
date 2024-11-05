import React, { useEffect } from "react"
import { Link, useNavigate, useLocation } from "react-router-dom"
import axios from "axios"
import "../assets/styles/Header.css"

const Header = ({ username, isAdmin, handleLogout }) => {
  const navigate = useNavigate()
  const location = useLocation()

  const checkAdminStatus = async () => {
    try {
      const response = await axios.get("http://localhost:3000/editprofile")
      const { accountStatus } = response.data
      if (accountStatus !== "Active") {
        console.warn("Account disabled. Logging out.")
        handleLogout()
      }
    } catch (error) {
      if (error.response && error.response.status === 401) {
        console.warn("Unauthorized access. Redirecting to login.")
        handleLogout()
      } else {
        console.error("Admin status check failed:", error)
      }
    }
  }

  useEffect(() => {
    checkAdminStatus()
  }, [location.pathname])

  return (
    <div className="header">
      <div className="welcome">Welcome, {username || "Guest"}</div>
      <nav>
        {isAdmin && (
          <>
            <Link to="/usermanagement" className={location.pathname === "/usermanagement" ? "active" : ""}>
              User Management System
            </Link>
            <span> | </span>
          </>
        )}
        <Link to="/taskmanagementsystem" className={location.pathname === "/taskmanagementsystem" ? "active" : ""}>
          Task Management System
        </Link>
      </nav>
      <div className="header-buttons">
        <button onClick={() => navigate("/editprofile")}>Profile</button>
        <button onClick={handleLogout}>Logout</button>
      </div>
    </div>
  )
}

export default Header
