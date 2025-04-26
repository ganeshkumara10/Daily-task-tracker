import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import LogoutIcon from "@mui/icons-material/Logout";
import Notesfinal from "./Notesfinal";
import Reminders from "./Reminders";
import {Tooltip,Typography,AppBar,Toolbar,Container,Snackbar,Alert} from "@mui/material";
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import InfoIcon from '@mui/icons-material/Info';
import CloseIcon from '@mui/icons-material/Close';

function Userpage() {

  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [openSnackbar, setOpenSnackbar] = useState(false);
  const [open, setOpen] = React.useState(false);
  const navigate = useNavigate();
  const firstName = localStorage.getItem("firstName") || "User";
  const lastName = localStorage.getItem("lastName") || "User";

  useEffect(() => {
    const token = localStorage.getItem("token");
    if (!token) {
      navigate("/login");
    }
  }, [navigate]);

  const handleLogout = () => {
    localStorage.clear();
    navigate("/");
  };

  const handleClickOpen = () => {
    setOpen(true);
  };

  const handleClose = () => {
    setOpen(false);
  };

  const handleCloseSnackbar = () => {
    setOpenSnackbar(false);
    setError("");
    setSuccess("");
  };

  return (
    <div>
      <AppBar position="static" color="success">
        <Toolbar>
          <Typography variant="h6" sx={{ flexGrow: 2, fontWeight:'bold' }}>
            Daily Task Tracker
          </Typography>
          <Tooltip title="Summary">
            <InfoIcon color="white" sx={{ mr:4, cursor:'pointer'}}  onClick={handleClickOpen}/>
          </Tooltip>
          <Dialog  open={open} onClose={handleClose} aria-labelledby="alert-dialog-title" aria-describedby="alert-dialog-description" sx={{
      "& .MuiDialog-container": {
        "& .MuiPaper-root": {
          width: "100%",
          maxWidth: "600px",height:"100%",maxHeight:"400px"
        },
      },
    }}>
          <DialogActions>
          <Tooltip title="Close">
          <CloseIcon  onClick={handleClose} sx={{cursor:'pointer'}}/></Tooltip>
        </DialogActions>
        <DialogContent>
          <DialogContentText id="alert-dialog-description">
            <Reminders/>
          </DialogContentText>
        </DialogContent>
        
      </Dialog>
          
          <Typography variant="subtitle1" sx={{ mr: 6 }}>
            Welcome, {firstName} {lastName}
          </Typography>
          <Tooltip title="Logout">
            <LogoutIcon
              onClick={handleLogout}
              sx={{ cursor: "pointer" }}
            />
          </Tooltip>
        </Toolbar>
      </AppBar>
      <Container sx={{ mt: 4, minHeight: "calc(100vh - 64px)" }}>
        <Notesfinal />
      </Container>
      <Snackbar
        open={openSnackbar}
        autoHideDuration={1500}
        onClose={handleCloseSnackbar}
        anchorOrigin={{ vertical: "top", horizontal: "center" }}
      ></Snackbar>
      <Alert
        onClose={handleCloseSnackbar}
        severity={success ? "success" : "error"}
        sx={{ width: "100%" }}
      ></Alert>
    </div>
  );
}

export default Userpage;