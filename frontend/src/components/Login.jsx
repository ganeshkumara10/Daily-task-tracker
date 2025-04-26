import React, { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import axios from "axios";
import {TextField,Button,Container,Typography,Box,Snackbar,Alert} from "@mui/material";

function Login() {
  const [loginData, setLoginData] = useState({ email: "", password: "" });
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [openSnackbar, setOpenSnackbar] = useState(false);
  const navigate = useNavigate();


  const handleLogin = async (e) => {
    e.preventDefault();
    try {
      const res = await axios.post("http://localhost:3000/login", loginData);
      localStorage.setItem("token", res.data.token);
      localStorage.setItem("firstName", res.data.firstname);
      localStorage.setItem("lastName", res.data.lastname);
      setSuccess("Login successful!");
      setOpenSnackbar(true);
      setTimeout(() => navigate("/user-page"), 2000);
    } catch (err) {
      setError(err.response?.data?.error || "Login failed");
      setOpenSnackbar(true);
    }
  };

  const handleCloseSnackbar = () => {
    setOpenSnackbar(false);
    setError("");
  };

  return (
    <Container  maxWidth="sm" sx={{ mt: 8, border: 1, borderColor: 'grey.500', borderRadius:2 }}>
      <Typography variant="h5" align="center" gutterBottom sx={{mt:2,fontWeight:'bold'}}>
        Login
      </Typography>
      <Box component="form" onSubmit={handleLogin} sx={{ mt: 2 }}>
        <TextField
          label="Email"
          type="email"
          value={loginData.email}
          onChange={(e) =>
            setLoginData({ ...loginData, email: e.target.value })
          }
          fullWidth
          margin="normal"
          required
        />
        <TextField
          label="Password"
          type="password"
          value={loginData.password}
          onChange={(e) =>
            setLoginData({ ...loginData, password: e.target.value })
          }
          fullWidth
          margin="normal"
          required
        />
        <Button type="submit" variant="contained" fullWidth sx={{ mt: 2 }} color="success">
          Login
        </Button>
      </Box>
      <Typography align="center" sx={{ mt: 3 }}>
        Don't have an account?{" "}
        <Button component={Link} to="/register">
          Register
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

export default Login;

