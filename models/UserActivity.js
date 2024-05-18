const { DataTypes } = require('sequelize');
const sequelize = require('../database');
const User = require('./User');

const UserActivity = sequelize.define('UserActivity', {
  action: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  timestamp: {
    type: DataTypes.DATE,
    allowNull: false,
  },
  device: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  browser: {
    type: DataTypes.STRING,
    allowNull: false,
  },
});

UserActivity.belongsTo(User, { foreignKey: 'userEmail', targetKey: 'email' });

module.exports = UserActivity;