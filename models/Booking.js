const mongoose = require("mongoose");
const DailyBookingCount = require("./DailyBookingCount");
const detectSeason = require("../utils/seasonDetector");
const getClimateData = require("../utils/climateFetcher");

const statusChangeSchema = new mongoose.Schema({
  status: { type: String, required: true },
  updatedBy: { type: mongoose.Schema.Types.ObjectId, ref: "Admin", required: true },
  updatedAt: { type: Date, default: Date.now },
}, { _id: false });

const bookingSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  bookingId: { type: String, unique: true },
  fullName: { type: String, required: true },
  email: { type: String, required: true },
  phone: { type: String, required: true },
  nationality: { type: String, required: true },
  destination: { type: String, required: true },
  country: { type: String },
  season: { type: String },
  avgTemperature: { type: Number },
  rainfall: { type: Number },
  budget: { type: String, required: true },
  startDate: { type: Date, required: true },
  endDate: { type: Date, required: true },
  createdAt: { type: Date, default: Date.now },
  travelers: { type: Number },
  travelerDetails: [
    {
      fullName: { type: String, required: true },
      nationality: { type: String, trim: true },
      birthdate: { type: Date },
      sex: { type: String, enum: ["Male", "Female"] },
      passportNumber: { type: String, trim: true },
      passportExpiry: { type: Date },
      emergencyName: { type: String, trim: true },
      emergencyContact: { type: String, trim: true },
      specialRequests: { type: String, trim: true },
    },
  ],
  approvalStatus: {
    type: String,
    enum: ["Pending", "Approved", "Declined"],
    default: "Pending",
  },
  paymentMethod: {
    type: String,
    enum: [ "gcash", "store"],
    required: true,
  },
  paymentId: { type: String },
  receiptUrl: { type: String },
  totalAmount: { type: Number, required: true },
  status: {
    type: String,
    enum: ["pending", "confirmed", "cancelled", "completed"],
    default: "pending",
  },
  archived: { type: Boolean, default: false },
  confirmedBy: { type: mongoose.Schema.Types.ObjectId, ref: "Admin" },
  completedBy: { type: mongoose.Schema.Types.ObjectId, ref: "Admin" },
  cancelledBy: { type: mongoose.Schema.Types.ObjectId, ref: "Admin" },
  confirmedAt: { type: Date },
  completedAt: { type: Date },
  cancelledAt: { type: Date },
  statusChangeHistory: [statusChangeSchema],
  tourDetails: {
    title: { type: String },
    destination: { type: String },
    country: { type: String },
    season: { type: String },
    duration: { type: Number },
    durationUnit: { type: String },
    price: { type: Number },
  },
  expiresAt: { type: Date },

  // 🧩 Internal flag to skip climate fetch during bulk updates
  skipClimateCheck: { type: Boolean, default: false, select: false },
});

// 🔄 Pre-save middleware
bookingSchema.pre("save", async function (next) {
  const isNew = this.isNew;

  // 🆔 Generate Booking ID
  if (isNew && !this.bookingId) {
    const date = new Date();
    const year = date.getFullYear().toString().slice(-2);
    const month = (date.getMonth() + 1).toString().padStart(2, "0");
    const day = date.getDate().toString().padStart(2, "0");
    const random = Math.floor(Math.random() * 10000).toString().padStart(4, "0");
    this.bookingId = `ABEE-${year}${month}${day}-${random}`;
  }

  // 🕒 Handle store payment expiry
  if (isNew && this.paymentMethod === "store" && !this.expiresAt) {
    const expiryDate = new Date();
    expiryDate.setHours(expiryDate.getHours() + 8);
    this.expiresAt = expiryDate;
  }

  // 🌍 Smart Global Season Detection
  if (this.startDate) {
    const seasonDetected = detectSeason({
      country: this.country,
      city: this.destination,
      date: this.startDate,
    });

    this.season = seasonDetected;
    if (this.tourDetails) {
      this.tourDetails.season = seasonDetected;
    }
  }

  // 🌦️ Fetch and store climate data for analytics (skip if flagged)
  if (!this.skipClimateCheck && this.startDate && this.destination) {
    const climate = await getClimateData(this.destination, this.country, this.startDate);
    if (climate) {
      this.avgTemperature = climate.avgTemperature;
      this.rainfall = climate.rainfall;
    }
  }

  // ⏱️ Auto-set timestamps on status change
  if (!isNew && this.isModified("status")) {
    const now = new Date();
    switch (this.status) {
      case "confirmed":
        if (!this.confirmedAt) this.confirmedAt = now;
        break;
      case "completed":
        if (!this.completedAt) this.completedAt = now;
        break;
      case "cancelled":
        if (!this.cancelledAt) this.cancelledAt = now;
        break;
    }
  }

  next();
});

// 📅 Post-save: Track daily booking stats
bookingSchema.post("save", async function () {
  try {
    const today = new Date();
    today.setUTCHours(0, 0, 0, 0);

    let dailyBooking = await DailyBookingCount.findOne({ date: today });

    if (dailyBooking) {
      dailyBooking.count += 1;
      await dailyBooking.save();
    } else {
      await DailyBookingCount.create({ date: today, count: 1 });
    }

    console.log(`✅ Booking ${this.bookingId} saved (${this.season})`);
  } catch (error) {
    console.error("❌ Error updating daily booking count:", error);
  }
});

module.exports = mongoose.model("Booking", bookingSchema);
