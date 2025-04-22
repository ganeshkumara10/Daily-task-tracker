import express from "express";
import cors from "cors";
import pg from "pg";
import bodyParser from "body-parser";
import env from "dotenv";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";

const app = express();
const port = process.env.PORT || 3000;

// Middleware
env.config();
app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(
  cors({
    origin: "http://localhost:3001",
    credentials: true,
  })
);
app.use(express.static("public"));

// PostgreSQL database connection
const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});
db.connect();

// JWT Secret Key
const jwtSecretKey = process.env.SECRET;

// Middleware to validate JWT token
const validateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) {
    return res.status(401).json({ error: "Access denied: No token provided" });
  }

  jwt.verify(token, jwtSecretKey, (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: "Invalid or expired token" });
    }
    req.userId = decoded.userId;
    req.userEmail = decoded.email;
    next();
  });
};

// POST carousel images
app.post("/carouselimages", async (req, res) => {
  const { imgurl, maker } = req.body;
  if (!imgurl || !maker) {
    return res.status(400).json({ error: "Image URL and maker are required" });
  }

  try {
    const result = await db.query(
      "INSERT INTO carouselimages (imgurl, maker) VALUES ($1, $2) RETURNING *",
      [imgurl, maker]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error("Error inserting carousel image:", err);
    res.status(500).json({ error: "Failed to add carousel image" });
  }
});

// GET carousel images
app.get("/carouselimages", async (req, res) => {
  try {
    const result = await db.query("SELECT * FROM carouselimages");
    res.json(result.rows);
  } catch (err) {
    console.error("Error fetching carousel images:", err);
    res.status(500).json({ error: "Failed to fetch carousel images" });
  }
});

// POST registration
app.post("/register", async (req, res) => {
  const { email, password, firstname, lastname } = req.body;
  if (!email || !password || !firstname || !lastname) {
    return res.status(400).json({ error: "Email, password, firstname, and lastname are required" });
  }

  try {
    const checkResult = await db.query("SELECT * FROM logindata WHERE email = $1", [email]);
    if (checkResult.rows.length > 0) {
      return res.status(409).json({ error: "Email already registered" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await db.query(
      "INSERT INTO logindata (email, password, firstname, lastname) VALUES ($1, $2, $3, $4) RETURNING id, email, firstname, lastname",
      [email, hashedPassword, firstname, lastname]
    );
    res.status(201).json({ success: true, message: "User registered successfully", user: result.rows[0] });
  } catch (err) {
    console.error("Error registering user:", err);
    res.status(500).json({ error: "Failed to register user" });
  }
});

// POST login
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }

  try {
    const result = await db.query("SELECT * FROM logindata WHERE email = $1", [email]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    const user = result.rows[0];
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ error: "Incorrect password" });
    }

    const token = jwt.sign({ userId: user.id, email: user.email }, jwtSecretKey, { expiresIn: "1h" });
    res.status(200).json({
      success: true,
      message: "Logged in successfully",
      token,
      firstname: user.firstname,
    });
  } catch (err) {
    console.error("Error logging in:", err);
    res.status(500).json({ error: "Failed to log in" });
  }
});

// GET user data for userpage
app.get("/user", validateToken, async (req, res) => {
  try {
    const result = await db.query("SELECT firstname, email FROM logindata WHERE id = $1", [req.userId]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error("Error fetching user:", err);
    res.status(500).json({ error: "Failed to fetch user information" });
  }
});

// GET pending tasks (completestatus = FALSE, currentstatus = FALSE)
app.get("/tasks", validateToken, async (req, res) => {
  try {
    const result = await db.query(
      "SELECT * FROM post WHERE user_id = $1 AND completestatus = FALSE AND currentstatus = FALSE ORDER BY timeofentry DESC",
      [req.userId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error("Error fetching pending tasks:", err);
    res.status(500).json({ error: "Failed to fetch pending tasks" });
  }
});

// GET completed tasks (completestatus = TRUE, currentstatus = FALSE)
app.get("/taskschange", validateToken, async (req, res) => {
  try {
    const result = await db.query(
      "SELECT * FROM post WHERE user_id = $1 AND completestatus = TRUE AND currentstatus = FALSE ORDER BY timeofentry DESC",
      [req.userId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error("Error fetching completed tasks:", err);
    res.status(500).json({ error: "Failed to fetch completed tasks" });
  }
});

// POST new task
app.post("/tasks", validateToken, async (req, res) => {
  const { task, type, timeofentry, completestatus, remindertime, currentstatus } = req.body;
  if (!task || !type || !remindertime) {
    return res.status(400).json({ error: "Task, type, and remindertime are required" });
  }

  try {
    const result = await db.query(
      "INSERT INTO post (user_id, task, type, timeofentry, completestatus, remindertime, currentstatus) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *",
      [req.userId, task, type, timeofentry, completestatus, remindertime, currentstatus]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error("Error adding task:", err);
    res.status(500).json({ error: "Failed to add task" });
  }
});

// PATCH task status (mark as done)
app.patch("/tasks/:id", validateToken, async (req, res) => {
  const { id } = req.params;
  const { completestatus, currentstatus } = req.body;

  try {
    const result = await db.query(
      "UPDATE post SET completestatus = $1, currentstatus = $2 WHERE id = $3 AND user_id = $4 RETURNING *",
      [completestatus, currentstatus, id, req.userId]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Task not found or unauthorized" });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error("Error updating task status:", err);
    res.status(500).json({ error: "Failed to update task status" });
  }
});

// PATCH task status (hide task)
app.patch("/dtasks/:id", validateToken, async (req, res) => {
  const { id } = req.params;
  const { completestatus, currentstatus } = req.body;

  try {
    const result = await db.query(
      "UPDATE post SET completestatus = $1, currentstatus = $2 WHERE id = $3 AND user_id = $4 RETURNING *",
      [completestatus, currentstatus, id, req.userId]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Task not found or unauthorized" });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error("Error updating task status:", err);
    res.status(500).json({ error: "Failed to update task status" });
  }
});

// PUT task content (edit task/type)
app.put("/tasks/:id", validateToken, async (req, res) => {
  const { id } = req.params;
  const { editedtask, editedtype } = req.body;
  if (!editedtask) {
    return res.status(400).json({ error: "Task content is required" });
  }

  try {
    const result = await db.query(
      "UPDATE post SET task = $1, type = $2 WHERE id = $3 AND user_id = $4 RETURNING *",
      [editedtask, editedtype, id, req.userId]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Task not found or unauthorized" });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error("Error updating task:", err);
    res.status(500).json({ error: "Failed to update task" });
  }
});

// PATCH completed task (undo)
app.patch("/taskschange/:id", validateToken, async (req, res) => {
  const { id } = req.params;
  const { completestatus, currentstatus } = req.body;

  try {
    const result = await db.query(
      "UPDATE post SET completestatus = $1, currentstatus = $2 WHERE id = $3 AND user_id = $4 RETURNING *",
      [completestatus, currentstatus, id, req.userId]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Task not found or unauthorized" });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error("Error undoing task:", err);
    res.status(500).json({ error: "Failed to undo task" });
  }
});


// GET data for overdue tasks (completestatus = FALSE, currentstatus = FALSE)
app.get("/remindertasks", validateToken, async (req, res) => {
  try {
    const result = await db.query(
      "SELECT * FROM post WHERE user_id = $1 AND remindertime - CURRENT_TIMESTAMP < INTERVAL '30 minutes' ORDER BY timeofentry DESC LIMIT 5",
      [req.userId]);
    res.json(result.rows);
  } catch (err) {
    console.error("Error fetching pending tasks:", err);
    res.status(500).json({ error: "Failed to fetch pending tasks" });
  }
});


// Start the server
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});