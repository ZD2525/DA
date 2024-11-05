import React from "react"

const TaskManagementSystem = ({ isAdmin, username }) => {
  return (
    <div style={{ padding: "20px" }}>
      <h3>Applications</h3>
      <button style={{ marginBottom: "20px" }}>Create App</button>
      <div>
        <div>
          <h4>App Name: Application 1</h4>
          <p>Description: Lorem Ipsum is simply dummy text of the printing and typesetting industry.</p>
          <p>Start Date: </p>
          <p>End Date:</p>
        </div>
        <hr />
        <div>
          <h4>App Name: Application 2</h4>
          <p>Description: Lorem Ipsum is simply dummy text of the printing and typesetting industry.</p>
          <p>Start Date: </p>
          <p>End Date: </p>
        </div>
      </div>
    </div>
  )
}

export default TaskManagementSystem
