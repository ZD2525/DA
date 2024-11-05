import React, { useState, useEffect } from "react"
import axios from "axios"
import Select from "react-select"
import { useNavigate } from "react-router-dom"
import Header from "./Header"
import "../assets/styles/UserManagement.css"

axios.defaults.withCredentials = true

const UserManagement = ({ fetchUserProfile, isAdmin, username, handleLogout }) => {
  const [users, setUsers] = useState([])
  const [groups, setGroups] = useState([])
  const [newGroup, setNewGroup] = useState("")
  const [newUser, setNewUser] = useState({
    username: "",
    email: "",
    password: "",
    group: [],
    accountStatus: "Active"
  })
  const [editingUser, setEditingUser] = useState(null)
  const [editFormData, setEditFormData] = useState({})
  const [errorMessage, setErrorMessage] = useState("")
  const [successMessage, setSuccessMessage] = useState("")
  const navigate = useNavigate()

  useEffect(() => {
    if (!isAdmin) {
      console.log("Non-admin access detected. Redirecting...")
      navigate("/taskmanagementsystem")
      return
    }
    fetchUserProfile()
    fetchUsers()
    fetchGroups()
  }, [isAdmin, fetchUserProfile, navigate])

  const fetchUsers = async () => {
    try {
      const response = await axios.get("http://localhost:3000/usermanagement")
      setUsers(response.data || [])
    } catch (error) {
      handleUnauthorizedAccess(error.response?.status)
    }
  }

  const fetchGroups = async () => {
    try {
      const response = await axios.get("http://localhost:3000/groups")
      setGroups(response.data?.map(group => ({ value: group, label: group })) || [])
    } catch (error) {
      handleUnauthorizedAccess(error.response?.status)
    }
  }

  const handleUnauthorizedAccess = status => {
    if (status === 401) {
      navigate("/login")
    } else if (status === 403) {
      navigate("/taskmanagementsystem")
    }
  }

  const validateAdminStatus = async () => {
    try {
      const profile = await fetchUserProfile()

      if (!profile) {
        console.error("Profile data is missing or fetch failed.")
        navigate("/login")
        return
      }

      if (!profile.isAdmin) {
        console.warn("User no longer has admin privileges. Redirecting...")
        navigate("/taskmanagementsystem")
        return
      }

      if (profile.accountStatus !== "Active") {
        console.warn("User account is disabled. Redirecting to login...")
        navigate("/login")
      }
    } catch (error) {
      console.error("Error validating admin status:", error)
      navigate("/login")
    }
  }

  const showMessageWithTimeout = (setterFunction, message, duration = 2000) => {
    setterFunction(message)
    setTimeout(() => {
      setterFunction("")
    }, duration)
  }

  const handleEditClick = async user => {
    await validateAdminStatus()
    try {
      const response = await axios.post("http://localhost:3000/get-user", { username: user.username })
      if (response.data) {
        setEditingUser(user.username)
        setEditFormData({
          email: response.data.email || "",
          accountStatus: response.data.accountStatus || "Active",
          groups: response.data.groups || [],
          password: ""
        })
        setErrorMessage("")
        setSuccessMessage("")
      }
    } catch (error) {
      showMessageWithTimeout(setErrorMessage, "Error fetching user details.")
    }
  }

  const handleSaveClick = async username => {
    await validateAdminStatus()
    const payload = {
      username,
      email: editFormData.email || "",
      accountStatus: editFormData.accountStatus,
      groups: editFormData.groups
    }

    if (editFormData.password) {
      payload.password = editFormData.password
    }

    try {
      await axios.put("http://localhost:3000/update-user", payload)
      showMessageWithTimeout(setSuccessMessage, "User updated successfully.")
      await fetchUsers()
      setEditingUser(null)
      setEditFormData({})
    } catch (error) {
      const backendMessage = error.response?.data?.error || "An error occurred while updating the user."
      showMessageWithTimeout(setErrorMessage, backendMessage)
    }
  }

  const handleCreateGroup = async () => {
    await validateAdminStatus()
    setErrorMessage("")
    setSuccessMessage("")
    try {
      await axios.post("http://localhost:3000/create-group", { group: newGroup })
      showMessageWithTimeout(setSuccessMessage, "Group created successfully.")
      fetchGroups()
      setNewGroup("")
    } catch (error) {
      const backendMessage = error.response?.data?.details?.[0]?.msg || "Error creating group."
      showMessageWithTimeout(setErrorMessage, backendMessage)
    }
  }

  const handleCreateUser = async () => {
    await validateAdminStatus()
    setErrorMessage("")
    setSuccessMessage("")
    try {
      await axios.post("http://localhost:3000/usermanagement", newUser)
      showMessageWithTimeout(setSuccessMessage, "User created successfully.")
      fetchUsers()
      setNewUser({ username: "", email: "", password: "", group: [], accountStatus: "Active" })
    } catch (error) {
      const backendMessage = error.response?.data?.details?.[0]?.msg || "Error creating user."
      showMessageWithTimeout(setErrorMessage, backendMessage)
    }
  }

  const handleGroupChange = selectedOptions => {
    setEditFormData(prevData => ({
      ...prevData,
      groups: selectedOptions ? selectedOptions.map(option => option.value) : []
    }))
  }

  const handleCancelClick = () => {
    setEditingUser(null)
    setEditFormData({})
    setErrorMessage("")
  }

  const handleEditInputChange = e => {
    const { name, value } = e.target
    setEditFormData(prevData => ({
      ...prevData,
      [name]: value || ""
    }))
  }

  return (
    <>
      <Header username={username} isAdmin={isAdmin} handleLogout={handleLogout} />
      <div className="user-management-container">
        <h2>User Management</h2>
        {successMessage && <div className="success-box">{successMessage}</div>}
        {errorMessage && <div className="error-box">{errorMessage}</div>}

        <div className="group-creation-section">
          <input type="text" placeholder="Enter group name" value={newGroup} onChange={e => setNewGroup(e.target.value || "")} />
          <button onClick={handleCreateGroup} disabled={!isAdmin}>
            Create Group
          </button>
        </div>

        {isAdmin && (
          <div className="create-user-section">
            <input type="text" placeholder="Username*" value={newUser.username} onChange={e => setNewUser({ ...newUser, username: e.target.value })} />
            <input type="email" placeholder="Email (optional)" value={newUser.email} onChange={e => setNewUser({ ...newUser, email: e.target.value })} />
            <input type="password" placeholder="Password*" value={newUser.password} onChange={e => setNewUser({ ...newUser, password: e.target.value })} />
            <Select
              isMulti
              options={groups}
              value={newUser.group.map(group => ({ value: group, label: group }))}
              onChange={selectedOptions =>
                setNewUser({
                  ...newUser,
                  group: selectedOptions ? selectedOptions.map(option => option.value) : []
                })
              }
              placeholder="Select Groups (optional)"
            />
            <select value={newUser.accountStatus} onChange={e => setNewUser({ ...newUser, accountStatus: e.target.value })}>
              <option value="Active">Active</option>
              <option value="Disabled">Disabled</option>
            </select>
            <button onClick={handleCreateUser}>Create User</button>
          </div>
        )}

        <table className="user-table">
          <thead>
            <tr>
              <th>Username</th>
              <th>Email</th>
              <th>Password</th>
              <th>Groups</th>
              <th>Status</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {users.map(user => (
              <tr key={user.username}>
                <td>{user.username}</td>
                <td>{editingUser === user.username ? <input type="text" name="email" value={editFormData.email || ""} onChange={handleEditInputChange} /> : user.email || ""}</td>
                <td>{editingUser === user.username ? <input type="password" name="password" value={editFormData.password || ""} onChange={handleEditInputChange} placeholder="Password" /> : "*".repeat(user.password.length)}</td>
                <td>{editingUser === user.username ? <Select isMulti value={(editFormData.groups || []).map(group => ({ value: group, label: group }))} options={groups} onChange={handleGroupChange} /> : (user.groups || []).join(", ") || ""}</td>
                <td>
                  {editingUser === user.username ? (
                    <select name="accountStatus" value={editFormData.accountStatus || "Active"} onChange={handleEditInputChange}>
                      <option value="Active">Active</option>
                      <option value="Disabled">Disabled</option>
                    </select>
                  ) : (
                    user.accountStatus
                  )}
                </td>
                <td>
                  {editingUser === user.username ? (
                    <>
                      <button onClick={() => handleSaveClick(user.username)} disabled={!isAdmin}>
                        Save
                      </button>
                      <button onClick={handleCancelClick}>Cancel</button>
                    </>
                  ) : (
                    <button onClick={() => handleEditClick(user)} disabled={!isAdmin}>
                      Edit
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  )
}

export default UserManagement
