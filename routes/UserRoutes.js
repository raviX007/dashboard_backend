const express = require("express");
const router = express.Router();
const userController = require("../controllers/userController");

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

// Register a new user
router.post("/register", userController.registerUser);

// Verify 2FA token and log in
router.post("/login", userController.loginUser);

// Verify 2FA token
router.post("/verify", userController.verifyToken);

// Logout
router.post("/logout",  userController.logoutUser);

// Get current user
router.get("/user",  userController.getCurrentUser);

router.get("/userAct",  userController.getUserActivity);

router.get("/userAdminAct",  userController.getAdminUserActivity);

router.post("/logoutCard",  userController.logoutCard);

router.post("/logoutAdm",  userController.logoutAdUser);

router.put("/deleteUser/:userId",userController.deleteUser);

router.post("/genToken",userController.handler);

router.post("/verify",userController.verifyToken);


module.exports = router;
