const dbConfig = require('./config/db.config');
const { Sequelize } = require('sequelize');

// Create a new Sequelize instance with the configuration
const sequelize = new Sequelize(dbConfig.DB, dbConfig.USER, dbConfig.PASSWORD, {
  host: dbConfig.HOST,
  port: dbConfig.DB_PORT,
  dialect: dbConfig.dialect,
  pool: dbConfig.pool,
  dialectOptions: {
    ssl: {
      require: true, // This will help you. But you will see nwe error
      rejectUnauthorized: false // This line will fix new error
    }
  }
});

module.exports = sequelize;