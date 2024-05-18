module.exports = {
    HOST: process.env.HOST,
    USER: process.env.USER,
    DB_PORT:process.env.DB_PORT,
    PASSWORD: process.env.PASSWORD,
    DB: process.env.DB,
    dialect: "postgres",
    pool: {
      max: 5,
      min: 0,
      acquire: 30000,
      idle: 10000
    }
  };