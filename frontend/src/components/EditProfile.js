import React, { useState, useEffect } from "react"
import { useNavigate } from "react-router-dom"
import axios from "axios"
import "../assets/styles/EditProfile.css"
axios.defaults.withCredentials = true

const EditProfile = () => {
  const [currentEmail, setCurrentEmail] = useState("")
  const [newEmail, setNewEmail] = useState("")
  const [newPassword, setNewPassword] = useState("")
  const [message, setMessage] = useState("")
  const [errorMessages, setErrorMessages] = useState([])
  const navigate = useNavigate()

  useEffect(() => {
    const fetchProfile = async () => {
      try {
        const response = await axios.get("http://localhost:3000/editprofile")
        setCurrentEmail(response.data.email || "No Email")
      } catch (error) {
        console.error("Error fetching profile:", error)
        if (error.response && error.response.status === 401) {
          navigate("/login")
        }
      }
    }
    fetchProfile()
  }, [navigate])

  const handleUpdate = async () => {
    setErrorMessages([])
    setMessage("")

    try {
      const response = await axios.put("http://localhost:3000/editprofile", {
        email: newEmail,
        newPassword
      })

      setMessage("Profile updated successfully")
      setCurrentEmail(newEmail || currentEmail)
      setNewEmail("")
      setNewPassword("")

      setTimeout(() => {
        setMessage("")
      }, 2000)
    } catch (error) {
      if (error.response && error.response.status === 400) {
        if (error.response.data.error === "Validation failed") {
          setErrorMessages(error.response.data.details.map(detail => detail.msg))
        } else {
          setErrorMessages([error.response.data.error || "An error occurred while updating the profile."])
        }
      } else {
        console.error("Error updating profile:", error)
        setErrorMessages(["An error occurred while updating the profile."])
      }

      setTimeout(() => {
        setErrorMessages([])
      }, 2000)
    }
  }

  // Handle Enter key press on input fields to trigger update
  const handleKeyPress = event => {
    if (event.key === "Enter") {
      handleUpdate()
    }
  }

  return (
    <div className="edit-profile-container">
      <h2>Update Info</h2>
      {message && <p className="message success-box">{message}</p>}

      {errorMessages.length > 0 && (
        <div className="error-box">
          <strong>Error:</strong>
          {errorMessages.map((msg, index) => (
            <span key={index}>
              {msg}
              {index < errorMessages.length - 1 ? ", " : ""}
            </span>
          ))}
        </div>
      )}

      <div className="form-group">
        <label>Current Email Address</label>
        <p className="email-display">{currentEmail}</p>
      </div>

      <div className="form-group">
        <label>New Email</label>
        <input type="text" value={newEmail} onChange={e => setNewEmail(e.target.value)} placeholder="Enter new email" onKeyDown={handleKeyPress} />
      </div>

      <div className="form-group">
        <label>New Password</label>
        <input type="password" value={newPassword} onChange={e => setNewPassword(e.target.value)} placeholder="Enter new password" onKeyDown={handleKeyPress} />
      </div>

      <button className="update-button" onClick={handleUpdate}>
        Update
      </button>
    </div>
  )
}

export default EditProfile
