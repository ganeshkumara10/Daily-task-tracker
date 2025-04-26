import React, { useEffect, useState } from "react";
import axios from "axios";
import { useNavigate } from "react-router-dom";
import Paper from '@mui/material/Paper';
import {Chart, PieSeries, Title} from '@devexpress/dx-react-chart-material-ui';
import { PieChart } from '@mui/x-charts/PieChart';
import { Typography } from "@mui/material";

function Reminders() {
   const [data, setData] = useState([]);
   const [piedata, setPieData] = useState({
    personalcount: 0,
    familycount: 0,
    workcount: 0,
    groupactivitycount: 0,
  });
  const token = localStorage.getItem("token");
  const firstName = localStorage.getItem("firstName") || "User";
  const lastName = localStorage.getItem("lastName") || "User";
  const navigate = useNavigate();

  useEffect(() => {
      
      if (!token) {
        navigate("/login");
        return;
      }
      fetchData();
    }, [token,navigate]);

    const fetchData = async () => {
      try {
        const res = await axios.get("http://localhost:3000/reminders", {
          headers: { Authorization: `Bearer ${token}` },
        });
        setData(res.data);
      } catch (err) {
        handleError(err, "Failed to fetch data");
      }
    };


    const pieFetchData = async () => {
      try {
        const res = await axios.get('http://localhost:3000/reminderspie', {
          headers: { Authorization: `Bearer ${token}` },
        });
    
        // Set data with fallback for missing fields
        setPieData({
          personalcount: res.data.personalcount || 0,
          familycount: res.data.familycount || 0,
          workcount: res.data.workcount || 0,
          groupactivitycount: res.data.groupactivitycount || 0,
        });
      } catch (err) {
        console.error('Error fetching pie chart data:', err);
        handleError(err, 'Failed to fetch pie chart data');
        // Set fallback data on error
        setPieData({
          personalcount: 0,
          familycount: 0,
          workcount: 0,
          groupactivitycount: 0,
        });
      }
    };
    
    const handleError = (err, defaultMsg) => {
      const msg = err.response?.data?.error || defaultMsg;
      if (err.response?.status === 401 || err.response?.status === 403) {
        navigate("/login");
      }
    };

    const file = [
      { task: 'Personal', value: Math.max(piedata.personalcount, 0) },
      { task: 'Family', value: Math.max(piedata.familycount, 0) },
      { task: 'Work', value: Math.max(piedata.workcount, 0) },
      { task: 'Group Activity', value: Math.max(piedata.groupactivitycount, 0) },
    ];

    useEffect(() => {
      if (token) {
        pieFetchData();
      }
    }, [token]);

  return (
    
    <div style={{alignItems:"center", alignContent:'center', textAlign:"center"}} >
      Hi, <b>{firstName} {lastName}</b><br/>
      Pending tasks: {data.pendingcount}<br/>
      <Typography variant="h5" sx={{mb:1}} fontWeight={300}>Tasks created till date: {data.count}</Typography><br/>
      

<PieChart
      series={[
        {
          data: file.map((item) => ({
            id: item.task,
            value: item.value,
            label: item.task,
          })),
          innerRadius: 30,
          outerRadius: 100,
          paddingAngle: 5,
          cornerRadius: 5,
          startAngle: -45,
          cx: 170
        },
      ]}
      width={300}
      height={200}
    />
    </div>
  )
}
export default Reminders