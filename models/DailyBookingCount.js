const mongoose = require("mongoose");

const dailyBookingCountSchema = new mongoose.Schema({
  date: { type: Date, required: true, unique: true },
  count: { type: Number, required: true }
});

module.exports = mongoose.model("DailyBookingCount", dailyBookingCountSchema);
