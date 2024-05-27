const express = require("express");
const app = express();
const http = require("http").createServer(app);
const io = require("socket.io")(http);
const jwt = require("jsonwebtoken");
const speakeasy = require("speakeasy");
const cookieParser = require("cookie-parser");
require("dotenv").config();
const cors = require('cors');
app.use(cors({
  origin: 'https://dashboard-ui-kw6h.vercel.app', // Allow only your frontend domain
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
const sequelize = require("./database");

const User = require("./models/User");
const UserActivity = require("./models/UserActivity");

// Import routes
const routes = require("./routes/UserRoutes");

// Import controllers
const userController = require("./controllers/userController");
app.use(cookieParser());
app.use(express.json());
app.use(cors());

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) return res.sendStatus(401);

  jwt.verify(
    token,
    process.env.JWT_SECRET || "your_default_secret_key",
    (err, user) => {
      if (err) return res.sendStatus(403);
      req.user = user;
      next();
    }
  );
};

// Use the imported routes
app.use("/mobilicis/api", routes);

// Socket.io connection
io.on("connection", (socket) => {
  console.log("A user connected");

  // Send user activities to the connected client
  UserActivity.findAll({ include: User })
    .then((activities) => {
      activities.forEach((activity) => {
        socket.emit("user-activity", activity);
      });
    })
    .catch((err) => {
      console.error("Error fetching user activities:", err);
    });
});

// Sync the database and start the server
sequelize
  .sync()
  .then(() => {
    http.listen(3000, () => {
      console.log("Server running on port 3000");
    });
  })
  .catch((err) => {
    console.error("Error connecting to the database:", err);
  });
