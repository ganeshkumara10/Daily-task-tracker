import React, { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { AppBar, Toolbar, Typography, Button, Container, Box} from "@mui/material";
import Footer from "./Footer";
import "../components/styles/homepage.css";
import axios from "axios";



function Homepage() {
  const [data, setData] = useState({ usercount: 0 });
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    fetchData();
  }, []);

      const fetchData = async () => {
        try {
          const res = await axios.get("http://localhost:3000/usercount");
          setData(res.data);
          setLoading(false);
        } catch (err) {
          console.error("Error fetching data:", err);
          setLoading(false);
          navigate("/");
        }
      };

    


  return (
    <div>
      <AppBar position="static" color="success">
        <Toolbar>
          <Typography variant="h6" sx={{ flexGrow: 2, fontWeight:'bold' }}>
            Daily Task Tracker
          </Typography>
          <Button variant="outlined" color="light" sx={{ mr: 1}} component={Link} to="/register">
            Register
          </Button>
          <Button variant="outlined" color="light" component={Link} to="/login">
            Login
          </Button>
        </Toolbar>
      </AppBar>
      <div className="frontHomepage">
      <Container sx={{ mt: 10,mb:10, textAlign: "left", width:'450px'}} fixed>
      <div className="homepageText">
      <Box sx={{height: '35vh', width:'50vh', textAlign:"left" }} >
      <Typography variant="h2" sx={{fontStyle:'italic'}}>
          Welcome to Task Tracker
      </Typography>
      </Box>
      <Typography variant="body1">
        "Effortlessly manage your daily tasks. Sign up or log in to begin!"
      </Typography>
      </div>
      </Container>
      <div className='imgPosition'>
      <img src="https://www.amitree.com/wp-content/uploads/2021/12/what-is-a-task-tracker-and-why-you-need-one.jpeg" alt="Image credits:Amitree Website" width={350} height={400} style={{marginRight:"80"}} />
      </div>
      </div>
      <div style={{ textAlign: "center", fontSize: 40 }}>
        {loading ? "Loading..." : `Our userbase has grown to ${data.usercount}`}
      </div>
      <Footer />
    </div>
  );
}

export default Homepage;