import React, { useState, useEffect } from "react";
import "../components/styles/Notesfinal.css";
import axios from "axios";
import {Box,FormControl,InputLabel,MenuItem,Select,TextField,Tooltip,Typography,Button,Snackbar,Alert} from "@mui/material";
import VisibilityOffIcon from "@mui/icons-material/VisibilityOff";
import AddBoxIcon from "@mui/icons-material/AddBox";
import EditIcon from "@mui/icons-material/Edit";
import DoneIcon from "@mui/icons-material/Done";
import { DemoContainer } from "@mui/x-date-pickers/internals/demo";
import { AdapterDayjs } from "@mui/x-date-pickers/AdapterDayjs";
import { LocalizationProvider } from "@mui/x-date-pickers/LocalizationProvider";
import { DateTimePicker } from "@mui/x-date-pickers/DateTimePicker";
import dayjs from "dayjs";
import duration from "dayjs/plugin/duration";
import SaveIcon from "@mui/icons-material/Save";
import UndoIcon from "@mui/icons-material/Undo";
import Chip from "@mui/material/Chip";
import AddAlertIcon from "@mui/icons-material/AddAlert";
import HistoryToggleOffIcon from "@mui/icons-material/HistoryToggleOff";
import { useNavigate } from "react-router-dom";

function Notesfinal() {
  const [inputText, setInputText] = useState("");
  const [inputType, setInputType] = useState("");
  const [remindertime, setReminderTime] = useState(dayjs());
  const [data, setData] = useState([]);
  const [completedData, setCompletedData] = useState([]);
  const [editingNoteId, setEditingNoteId] = useState(null);
  const [editedText, setEditedText] = useState("");
  const [editedType, setEditedType] = useState("");
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [openSnackbar, setOpenSnackbar] = useState(false);
  const navigate = useNavigate();
  const token = localStorage.getItem("token");

  // Track current date & time
  dayjs.extend(duration);
  const calculateTimeRemaining = (remindertime) => {
    const now = dayjs();
    const reminder = dayjs(remindertime, "D/M/YYYY, h:mm:ss a");
    const diff = dayjs.duration(reminder.diff(now));
    const days = Math.floor(diff.asDays());
    const hours = diff.hours();
    const minutes = diff.minutes();

    if (diff.asMilliseconds() <= 0) {
      return "Task is overdue!";
    } else if (days === 0 && hours === 0) {
      return `${minutes} Mins`;
    } else if (days === 0) {
      return `${hours} Hrs ${minutes} Mins`;
    } else {
      return `${days} Days ${hours} Hrs ${minutes} Mins`;
    }
  };

  // When ever the dependencies(token,navigate) change, render the functions inside useEffect  
  useEffect(() => {
    
    if (!token) {
      navigate("/login");
      return;
    }
    fetchData();
    fetchUndoData();
  }, [token, navigate]);

  const fetchData = async () => {
    try {
      const res = await axios.get("http://localhost:3000/tasks", {
        headers: { Authorization: `Bearer ${token}` },
      });
      setData(res.data);
    } catch (err) {
      handleError(err, "Failed to fetch pending tasks");
    }
  };

  const fetchUndoData = async () => {
    try {
      const res = await axios.get("http://localhost:3000/taskschange", {
        headers: { Authorization: `Bearer ${token}` },
      });
      setCompletedData(res.data);
    } catch (err) {
      handleError(err, "Failed to fetch completed tasks");
    }
  };

  const handleError = (err, defaultMsg) => {
    const msg = err.response?.data?.error || defaultMsg;
    if (err.response?.status === 401 || err.response?.status === 403) {
      localStorage.clear();
      navigate("/login");
    }
    setError(msg);
    setOpenSnackbar(true);
  };

  const handleCloseSnackbar = () => {
    setOpenSnackbar(false);
    //setError("");
    //setSuccess("");
  };

  const handleChangePara = (event) => {
    setInputText(event.target.value);
  };

  const handleChangeType = (event) => {
    setInputType(event.target.value);
  };

  const handleChangeReminderTime = (newValue) => {
    setReminderTime(newValue);
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    if (!inputText || !inputType || !remindertime) {
      setError("Task, type, and reminder time are required");
      setOpenSnackbar(true);
      return;
    }

    const newNote = {
      task: inputText,
      type: inputType,
      timeofentry: new Date().toLocaleString(),
      completestatus: false,
      currentstatus: false,
      remindertime: remindertime.format("D/M/YYYY, h:mm:ss a"),
    };

    try {
      await axios.post("http://localhost:3000/tasks", newNote, {
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
      });
      setSuccess("Task added successfully");
      setOpenSnackbar(true);
      setInputText("");
      setInputType("");
      setReminderTime(dayjs());
      fetchData();
    } catch (err) {
      handleError(err, "Failed to add task");
    }
  };

  const handleCurrentStatus = async (id) => {
    try {
      await axios.patch(
        `http://localhost:3000/dtasks/${id}`,
        { completestatus: true, currentstatus: true },
        {
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${token}`,
          },
        }
      );
      setSuccess("Task hidden successfully");
      setOpenSnackbar(true);
      fetchData();
      fetchUndoData();
    } catch (err) {
      handleError(err, "Failed to hide task");
    }
  };

  const handleEdit = (note) => {
    setEditingNoteId(note.id);
    setEditedText(note.task);
    setEditedType(note.type);
  };

  const handleSave = async (id) => {
    if (!editedText) {
      setError("Task content is required");
      setOpenSnackbar(true);
      return;
    }

    const updatedNote = {
      editedtask: editedText,
      editedtype: editedType,
    };

    try {
      await axios.put(`http://localhost:3000/tasks/${id}`, updatedNote, {
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
      });
      setSuccess("Task updated successfully");
      setOpenSnackbar(true);
      setEditingNoteId(null);
      fetchData();
    } catch (err) {
      handleError(err, "Failed to update task");
    }
  };

  const handleStatus = async (id) => {
    try {
      await axios.patch(
        `http://localhost:3000/tasks/${id}`,
        { completestatus: true, currentstatus: false },
        {
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${token}`,
          },
        }
      );
      setSuccess("Task marked as done");
      setOpenSnackbar(true);
      fetchData();
      fetchUndoData();
    } catch (err) {
      handleError(err, "Failed to mark task as done");
    }
  };

  const handleChangeStatus = async (id) => {
    try {
      await axios.patch(
        `http://localhost:3000/taskschange/${id}`,
        { completestatus: false, currentstatus: false },
        {
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${token}`,
          },
        }
      );
      setSuccess("Task marked as undone");
      setOpenSnackbar(true);
      fetchData();
      fetchUndoData();
    } catch (err) {
      handleError(err, "Failed to undo task");
    }
  };

  return (
    <Box sx={{ p: 2 }}>
      <form onSubmit={handleSubmit}>
        <Box sx={{ display: "flex", alignItems: "center", mb: 2 }}>
          <FormControl sx={{ width: "20%", mr: 1 }} margin="dense">
            <InputLabel id="type-select-label">Type</InputLabel>
            <Select
              labelId="type-select-label"
              id="type-select"
              value={inputType}
              label="Type"
              onChange={handleChangeType}
            >
              <MenuItem value="Work">Work</MenuItem>
              <MenuItem value="Personal">Personal</MenuItem>
              <MenuItem value="Group Activity">Group Activity</MenuItem>
              <MenuItem value="Family">Family</MenuItem>
            </Select>
          </FormControl>
          <LocalizationProvider dateAdapter={AdapterDayjs}>
            <DemoContainer components={["DateTimePicker"]}>
              <DateTimePicker
                label="Reminder"
                value={remindertime}
                onChange={handleChangeReminderTime}
              />
            </DemoContainer>
          </LocalizationProvider>
          <Tooltip title="Add Task">
            <Button type="submit"variant="contained" size="large" color="success" startIcon={<AddBoxIcon />} sx={{ ml: 1 }}>
              Add
            </Button>
          </Tooltip>
        </Box>
        <TextField
          fullWidth
          label="Task"
          value={inputText}
          onChange={handleChangePara}
          margin="dense"
        />
      </form>

      <Box sx={{ mt: 4 }}>
        <Typography variant="h6" gutterBottom>
          Pending Tasks ⌛
        </Typography>
        <hr />
        <Box sx={{ mt: 2 }}>
          {data.map((item) => (
            <Box
              key={item.id}
              sx={{ mb: 2, p: 2, border: "1px solid #ddd", borderRadius: 2 }}
            >
              {editingNoteId === item.id ? (
                <Box sx={{ display: "flex", alignItems: "center" }}>
                  <FormControl sx={{ width: "30%", mr: 1 }} margin="dense">
                    <InputLabel id="edit-type-select-label">Type</InputLabel>
                    <Select
                      labelId="edit-type-select-label"
                      value={editedType}
                      label="Type"
                      onChange={(e) => setEditedType(e.target.value)}
                    >
                      <MenuItem value="Work">Work</MenuItem>
                      <MenuItem value="Personal">Personal</MenuItem>
                      <MenuItem value="Group Activity">Group Activity</MenuItem>
                      <MenuItem value="Family">Family</MenuItem>
                    </Select>
                  </FormControl>
                  <TextField
                    sx={{ width: "60%" }}
                    value={editedText}
                    label="Task"
                    onChange={(e) => setEditedText(e.target.value)}
                  />
                  <Tooltip title="Save Changes">
                    <SaveIcon
                      color="success"
                      onClick={() => handleSave(item.id)}
                      sx={{ cursor: "pointer", ml: 1 }}
                    />
                  </Tooltip>
                </Box>
              ) : (
                <Box sx={{ display: "flex", alignItems: "center" }}>
                  <TextField
                    sx={{ width: "30%", mr: 1 }}
                    value={item.type}
                    disabled
                    size="small"
                  />
                  <TextField
                    sx={{ width: "60%" }}
                    value={item.task}
                    disabled
                    size="small"
                  />
                </Box>
              )}
              <Box
                sx={{ display: "flex", justifyContent: "space-between", mt: 1 }}
              >
                <Box>
                  <Tooltip title="Task Created">
                    <Chip
                      label={item.timeofentry}
                      variant="outlined"
                      size="small"
                      color="info"
                      icon={<HistoryToggleOffIcon />}
                    />
                  </Tooltip>
                  <Tooltip title="Task Reminder">
                    <Chip
                      label={item.remindertime}
                      sx={{ ml: 1 }}
                      size="small"
                      variant="outlined"
                      color="warning"
                      icon={<AddAlertIcon />}
                    />
                  </Tooltip>
                  <Typography
                    variant="body2"
                    sx={{ mt: 1, color: "text.secondary" }}
                  >
                    {calculateTimeRemaining(item.remindertime)}
                  </Typography>
                </Box>
                <Box sx={{ display: "flex", alignItems: "center" }}>
                  {editingNoteId !== item.id && (
                    <Tooltip title="Edit Task">
                      <EditIcon
                        color="secondary"
                        onClick={() => handleEdit(item)}
                        sx={{ cursor: "pointer", mr: 1 }}
                      />
                    </Tooltip>
                  )}
                  <Tooltip title="Mark as Done">
                    <DoneIcon
                      color="primary"
                      onClick={() => handleStatus(item.id)}
                      sx={{ cursor: "pointer", mr: 1 }}
                    />
                  </Tooltip>
                  <Tooltip title="Hide Task">
                    <VisibilityOffIcon
                      color="secondary"
                      onClick={() => handleCurrentStatus(item.id)}
                      sx={{ cursor: "pointer", mr: 1 }}
                    />
                  </Tooltip>
                </Box>
              </Box>
            </Box>
          ))}
        </Box>

        <Typography variant="h6" gutterBottom sx={{ mt: 4 }}>
          Completed Tasks ✅
        </Typography>
        <hr />
        <Box sx={{ mt: 2 }}>
          {completedData.map((item) => (
            <Box
              key={item.id}
              sx={{ mb: 2, p: 2, border: "1px solid #ddd", borderRadius: 2 }}
            >
              <Box sx={{ display: "flex", alignItems: "center" }}>
                <TextField
                  sx={{ width: "30%", mr: 1 }}
                  value={item.type}
                  disabled
                  size="small"
                />
                <TextField
                  sx={{ width: "60%" }}
                  value={item.task}
                  disabled
                  size="small"
                />
              </Box>
              <Box
                sx={{ display: "flex", justifyContent: "space-between", mt: 1 }}
              >
                <Tooltip title="Task Reminder">
                  <Chip
                    label={item.remindertime}
                    size="small"
                    variant="outlined"
                    color="success"
                    icon={<AddAlertIcon />}
                  />
                </Tooltip>
                <Tooltip title="Undo">
                  <UndoIcon
                    color="secondary"
                    onClick={() => handleChangeStatus(item.id)}
                    sx={{ cursor: "pointer" }}
                  />
                </Tooltip>
              </Box>
            </Box>
          ))}
        </Box>
      </Box>

      <Snackbar
        open={openSnackbar}
        autoHideDuration={7500}
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
    </Box>
  );
}

export default Notesfinal;
