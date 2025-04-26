import React from "react";
import { useNavigate } from "react-router-dom";
import { AppBar, Toolbar, Typography, Button, Container } from "@mui/material";

function Homepage() {
  const navigate = useNavigate();
  const handleLoginClick = () => {
    navigate("/login"); // Navigate to the login page
  };
  const handleRegisterClick = () => {
    navigate("/register"); // Navigate to the register page
  };
  
  return (
    <div>
      <AppBar position="static" color="success">
        <Toolbar>
          <Typography variant="h6" sx={{ flexGrow: 1 }}>
            Task Tracker
          </Typography>
          <Button color="inherit" onClick={handleRegisterClick}>
            Register
          </Button>
          <Button color="inherit" onClick={handleLoginClick}>
            Login
          </Button>
        </Toolbar>
      </AppBar>
      <Container sx={{ mt: 8, textAlign: "center" }}>
        <Typography variant="h4" gutterBottom>
          Welcome to Task Tracker
        </Typography>
        <Typography variant="body1">
          Manage your tasks efficiently. Register or log in to get started.
        </Typography>
      </Container>
    </div>
  );
}

export default Homepage;