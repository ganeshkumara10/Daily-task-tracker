import React, { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import axios from "axios";
import {TextField,Button,Container,Typography,Box,Snackbar,Alert} from "@mui/material";

//step 1: set usestate to take inputs and update Regestration data
//step 2:On form submit run the function to POST data and show the status
//Step 3: To show the status using snackbar to display success or alert text
function Register() {
  const [registerData, setRegisterData] = useState({email: "",password: "",firstname: "",lastname: ""});
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [openSnackbar, setOpenSnackbar] = useState(false);
  const navigate = useNavigate();

  const handleRegister = async (e) => {
    e.preventDefault();
    try {
      await axios.post("http://localhost:3000/register", registerData);
      setSuccess("Registration successful! Please log in.");
      setOpenSnackbar(true);
      setTimeout(() => navigate("/login"), 2000);
    } catch (err) {
      setError(err.response?.data?.error || "Registration failed");
      setOpenSnackbar(true);
    }
  };

  const handleCloseSnackbar = () => {
    setOpenSnackbar(false);
    // setError("");
    // setSuccess("");
  };


  return (
    <Container maxWidth="sm" sx={{ mt: 8, border: 1, borderColor: 'grey.500', borderRadius:2 }}>
      <Typography variant="h4" align="center" gutterBottom sx={{mt:2,fontWeight:'bold'}}>
        Register
      </Typography>
      <Box component="form" onSubmit={handleRegister} sx={{ mt: 2 }}>
        <TextField
          label="First Name"
          value={registerData.firstname}
          onChange={(e) =>
            setRegisterData({ ...registerData, firstname: e.target.value })
          }
          fullWidth
          margin="normal"
          required
        />
        <TextField
          label="Last Name"
          value={registerData.lastname}
          onChange={(e) =>
            setRegisterData({ ...registerData, lastname: e.target.value })
          }
          fullWidth
          margin="normal"
          required
        />
        <TextField
          label="Email"
          type="email"
          value={registerData.email}
          onChange={(e) =>
            setRegisterData({ ...registerData, email: e.target.value })
          }
          fullWidth
          margin="normal"
          required
        />
        <TextField
          label="Password"
          type="password"
          value={registerData.password}
          onChange={(e) =>
            setRegisterData({ ...registerData, password: e.target.value })
          }
          fullWidth
          margin="normal"
          required
        />
        <Button type="submit" variant="contained" fullWidth sx={{ mt: 2 }} color="success">
          Register
        </Button>
      </Box>
      <Typography align="center" sx={{ mt: 3 }}>
        Already have an account?{" "}
        <Button component={Link} to="/login">
          Log in
        </Button>
      </Typography>
      <Snackbar
        open={openSnackbar}
        autoHideDuration={1500}
        onClose={handleCloseSnackbar}
        anchorOrigin={{ vertical: "top", horizontal: "center" }}
      >
        <Alert
          onClose={handleCloseSnackbar}
          severity={success ? "success" : "error"}
          sx={{ width: "100%" }}
        >
          {success || error}
        </Alert>
      </Snackbar>
    </Container>
  );
}

export default Register;