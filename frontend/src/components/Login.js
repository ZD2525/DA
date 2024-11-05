import React, { useState } from "react"
import axios from "axios"
import { useNavigate } from "react-router-dom"
import "../assets/styles/Login.css"

axios.defaults.withCredentials = true

const Login = ({ fetchUserProfile }) => {
  const [loginUsername, setLoginUsername] = useState("")
  const [password, setPassword] = useState("")
  const [error, setError] = useState(null)
  const navigate = useNavigate()

  const handleLogin = async e => {
    e.preventDefault()
    setError(null)

    try {
      const response = await axios.post("http://localhost:3000/login", {
        username: loginUsername,
        password
      })

      if (response.data.user) {
        await fetchUserProfile()
        navigate("/taskmanagementsystem")
      } else {
        throw new Error("User data not found in the response.")
      }
    } catch (err) {
      setError(err.response?.data?.error || "An error occurred during login.")
      console.error("Login failed:", err)
    }
  }

  return (
    <div className="login-container">
      <h2>Login</h2>
      {error && <div className="error">{error}</div>}
      <form onSubmit={handleLogin} className="login-form">
        <div className="form-group">
          <label>Username</label>
          <input type="text" className="login-input" value={loginUsername} onChange={e => setLoginUsername(e.target.value)} />
        </div>
        <div className="form-group">
          <label>Password</label>
          <input type="password" className="login-input" value={password} onChange={e => setPassword(e.target.value)} />
        </div>
        <button type="submit" className="login-button">
          Log In
        </button>
      </form>
    </div>
  )
}

export default Login
