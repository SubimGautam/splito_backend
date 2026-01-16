const mongoose = require("mongoose");

const connectDB = async () => {
  try {
    const conn = await mongoose.connect(process.env.LOCAL_DATABASE_URI);
    console.log(
      `MongoDB connected to : ${conn.connection.host}`.yellow.underline.bold
    );
  } catch (error) {
    console.error(`MongoDB connection error: ${error}`.red.underline.bold);
    process.exit(1); // Exit process on DB connection failure
  }
};

module.exports = connectDB;
