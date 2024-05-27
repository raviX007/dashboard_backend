const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');
const User = require('../models/User');
const UserActivity = require('../models/UserActivity');
const userAgent = require('user-agent');
const { Op } = require('sequelize');
const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser');
// Register a new user

const parseUserAgent = (uaString) => {
    // Regular expression for browser detection
    const browserRegex = /(Chrome|Firefox|Safari|Opera|Edge|MSIE|Trident)\/([\d.]+)/i;
    const browserMatch = uaString.match(browserRegex);
  
    let browserName = 'Unknown';
    let browserVersion = 'Unknown';
  
    if (browserMatch) {
      browserName = browserMatch[1];
      browserVersion = browserMatch[2];
    }
  
    // Regular expression for device detection
    const deviceRegex = /(Windows NT|Macintosh|iPad|iPhone|Android|Linux)/i;
    const deviceMatch = uaString.match(deviceRegex);
  
    const deviceName = deviceMatch ? deviceMatch[1] : 'Unknown';
  
    return { browserName, browserVersion, deviceName };
  };



exports.registerUser = async (req, res) => {
  const salt=await bcrypt.genSalt(10);
  const hashedPassword=await bcrypt.hash(req.body.password,salt)
  const email = req.body.email;
  const password = hashedPassword;
  //const temporarySecret = speakeasy.generateSecret({ length: 20 });
  const isAdmin=req.body.isAdmin;
  const isDeleted=req.body.isDeleted;
  // Check if the user already exists
  const existingUser = await User.findOne({ where: { email } });
  if (existingUser) {
    return res.status(409).json({ message: 'User already exists' });
  }

  // Create a new user
  const user = await User.create({ email, password, isAdmin,isDeleted });

  res.json({ message:"User Registered" });
};

// Verify 2FA token and log in
exports.loginUser = async (req, res) => {
    const email = req.body.email;
    const password = req.body.password;
    const uaString = req.headers['user-agent'];
    console.log("ua", uaString);
    const { browserName, deviceName } = parseUserAgent(uaString);
    console.log("Browser:", browserName);
    console.log("Device:", deviceName);
  
    const user = await User.findOne({ where: { email } });
  
    if (!user || user.password !== password) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
  // if(!await bcrypt.compare( req.body.password,user.password)){
  //   return res.status(401).json({ message: 'Invalid credentials from bcrypt' });
  // }
    const isAdmin = user.isAdmin || false; // Assuming you have an 'isAdmin' field in your User model
  
    const token = jwt.sign( {id:user.id},process.env.JWT_SECRET);
    //const jwtToken = jwt.sign({ email }, process.env.JWT_SECRET || 'your_default_secret_key');

    res.cookie('jwt',token, {
      httpOnly: true,
      maxAge:24*60*60*1000//day
    })
    const activity = {
      action: 'login',
      timestamp: new Date(),
      device: deviceName,
      userEmail: email,
      browser: browserName,
    };
  
    // Create a new user activity
    await UserActivity.create(activity);
  
    res.json({ message: "user logged in", isAdmin });
  };
// Verify 2FA token

exports.handler=async(req, res)=> {
  if (req.method === 'POST') {
    const { email } = req.body;

    try {
      // Find the user by email
      const user = await User.findOne({ email });

      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }

      // Generate a new temporary secret
      const temporarySecret = speakeasy.generateSecret({ length: 20 });

      // Update the user's temporarySecret in the database
      user.temporarySecret = temporarySecret.base32;
      await user.save();

      // Generate the token
      const token = speakeasy.totp({
        secret: temporarySecret.base32,
        encoding: 'base32',
      });

      // Return the token
      res.status(200).json({ token });
    } catch (error) {
      console.error('Error generating token:', error);
      res.status(500).json({ error: 'Failed to generate token' });
    }
  } else {
    res.status(405).json({ error: 'Method not allowed' });
  }
}
exports.verifyToken = async (req, res) => {
  const { email, token } = req.body;

  try {
    // Find the user by email
    const user = await User.findOne({ where: { email } });
    const isAdmin = user.isAdmin;
    if (!user) {
      return res.status(404).json({ isValid: false, message: 'User not found' });
    }

    // Verify the token
    const isValidToken = speakeasy.totp.verify({
      secret: user.temporarySecret,
      encoding: 'base32',
      token,
      window: 1, // Adjust the window as needed
    });

    if (!isValidToken) {
      return res.status(401).json({ isValid: false, message: 'Invalid 2FA token' });
    }

    res.json({ isValid: true ,isAdmin});
  } catch (error) {
    console.error('Error verifying token:', error);
    res.status(500).json({ isValid: false, message: 'Internal server error' });
  }
};
exports.getUserActivity = async (req, res) => {

    const  userEmail  = req.query["userEmail"];
  console.log("userEmail:", userEmail);
  console.log("req.query",req.query["userEmail"]);
  console.log("req.params",req.params);
    try {
      const userActivities = await UserActivity.findAll({
        where: { userEmail,action:'login' },
        order: [['timestamp', 'DESC']], // Optional: Order by timestamp in descending order
      });
  
      res.status(200).json(userActivities);
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: 'Internal Server Error' });
    }
  };
// Logout
// Logout
exports.logoutUser = async (req, res) => {
    try {
      const userEmail = req.body.userEmail;
      console.log("userEmail: ", userEmail);
  
      // Find the latest activity for the user
      const latestActivities = await UserActivity.findAll({
        where: { userEmail },
        order: [['timestamp', 'DESC']],
      });
  
      // If a previous activity exists, update it
      if (latestActivities.length > 0) {
        const latestActivity = latestActivities[0];
        const updatedActivity = {
          action: 'logout',
          timestamp: new Date(),
        };
  
        await latestActivity.update(updatedActivity);
        //res.cookie('jwt','',{maxAge:0})
      } else {
        res.status(404).send({ message: "not found" });
      }
  
      res.sendStatus(200);
    } catch (error) {
      console.error('Error:', error);
      res.status(500).send({ message: 'An error occurred' });
    }
    
  };

  exports.getAdminUserActivity = async (req, res) => {
    try {
      // Fetch all users
      const users = await User.findAll({
        attributes: ['id', 'email'],
      });
  
      // Fetch activities for users who have 'login' action
      const userActivities = await UserActivity.findAll({
        attributes: ['id', 'action', 'timestamp', 'device', 'browser', 'userEmail'],
        where: {
          action: 'login',
          userEmail: {
            [Op.in]: users.map((user) => user.email),
          },
        },
      });
  
      // Group activities by user email
      const groupedActivities = userActivities.reduce((acc, activity) => {
        if (!acc[activity.userEmail]) {
          acc[activity.userEmail] = {
            email: activity.userEmail,
            activities: [],
          };
        }
  
        acc[activity.userEmail].activities.push({
          id: activity.id,
          action: activity.action,
          timestamp: activity.timestamp,
          device: activity.device,
          browser: activity.browser,
        });
  
        return acc;
      }, {});
  
      // Map users with their corresponding activities
      const result = users.map((user) => ({
        id: user.id,
        email: user.email,
        activities: groupedActivities[user.email]?.activities || [],
      }));
  
      res.json(result);
    } catch (error) {
      console.error('Error fetching user activities:', error);
      res.status(500).json({ error: 'Internal Server Error' });
    }
  };
    
exports.logoutCard = async (req, res) => {
    const  userEmail  = req.body.userEmail;
    const uaString = req.headers['user-agent'];
    console.log("ua",uaString)
    
    const { browserName, deviceName } = parseUserAgent(uaString);
  
    try {
      // Find the activity matching the browser and device
      const activityToLogout = await UserActivity.findOne({
        where: { userEmail: userEmail,browser:browserName, device:deviceName, action: 'login' },
      });
  
      if (activityToLogout) {
        // Update the logout status of the activity
        activityToLogout.action = 'logout';
        activityToLogout.timestamp = new Date();
        await activityToLogout.save();
        res.status(200).json({ message: 'User logged out successfully' });
      } else {
        res.status(404).json({ message: 'Activity not found' });
      }
    } catch (error) {
      console.error('Error during card logout:', error);
      res.status(500).json({ message: 'An error occurred during card logout' });
    }
  };

  async function logoutSession(session) {
    console.log(`Logging out session: ${session.activityId}`);
    // Implement your logic to log out the user from the specific session
  }
  
  // Function to log out a user from all sessions
  async function logoutAllSessions(user) {
    console.log(`Logging out user: ${user.email}`);
    // Implement your logic to log out the user from all sessions
  }
  
  // Function to find a user by their ID
  async function findUserById(userId) {
    return User.findByPk(userId);
  }
  exports.logoutAdUser = async (req, res) => {
    try {
      const { userId, activityId, logoutAll } = req.body;
  
      // Find the user by their ID
      const user = await findUserById(userId);
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }
  
      if (logoutAll) {
        // Logout the user from all activities
        await UserActivity.update(
          { action: 'logout', timestamp: new Date() },
          { where: { userEmail: user.email, action: 'login' } }
        );
      } else {
        // Logout the user from the specific activity
        const activity = await UserActivity.findOne({
          where: { id: activityId, userEmail: user.email, action: 'login' },
        });
        if (!activity) {
          return res.status(404).json({ error: 'Activity not found' });
        }
        activity.action = 'logout';
        activity.timestamp = new Date();
        await activity.save();
      }
  
      res.status(200).json({ message: 'Logout successful' });
    } catch (error) {
      console.error('Error during logout:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  };

  exports.deleteUser = async(req,res) => {
    try {
        const userId = req.params.userId;
    
        // Find the user by their ID
        const user = await User.findByPk(userId);
    
        if (!user) {
          return res.status(404).json({ error: 'User not found' });
        }
    
        // Update the isDeleted field for the user
        user.isDeleted = true;
        await user.save();
    
        res.status(200).json({ message: 'User deleted successfully' });
      } catch (error) {
        console.error('Error deleting user:', error);
        res.status(500).json({ error: 'Internal server error' });
      }
}
// Get current user
exports.getCurrentUser = async (req, res) => {
  try{
    // const cookie =req.cookies['jwt'];

    // const claims= jwt.verify(cookie,process.env.JWT_SECRET);
  
    // if(!claims){
    //   return res.status(401).send({message: 'unauthorized'
    // })
    // }
    const user = await User.findOne({ where: { email: req.body.email } });
    res.json({ name: user.email });
  }catch(e){
    return res.status(401).send({message:'unauthorized'})
  }
  
};