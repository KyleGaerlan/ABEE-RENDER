// routes/insights.js
const express = require("express");
const router = express.Router();
const Booking = require("../models/Booking");
const User = require("../models/User");

// 🧭 Helper functions
function startOfMonth(year, month) {
  return new Date(year, month, 1);
}

function endOfMonth(year, month) {
  return new Date(year, month + 1, 0, 23, 59, 59);
}

function startOfYear(year) {
  return new Date(year, 0, 1);
}

function endOfYear(year) {
  return new Date(year, 11, 31, 23, 59, 59);
}

// ===================================================
// 🗓 WEEKLY INSIGHTS (based on selected month & year)
// ===================================================
router.get("/weekly", async (req, res) => {
  try {
    const now = new Date();
    const selectedMonth = req.query.month ? parseInt(req.query.month) : now.getMonth();
    const selectedYear = req.query.year ? parseInt(req.query.year) : now.getFullYear();

    const startDate = startOfMonth(selectedYear, selectedMonth);
    const endDate = endOfMonth(selectedYear, selectedMonth);

    // Bookings for selected month
    const bookings = await Booking.find({
      createdAt: { $gte: startDate, $lte: endDate },
    });

    // Total bookings
    const total = bookings.length;

    // New users in the same period
    const newUsers = await User.countDocuments({
      createdAt: { $gte: startDate, $lte: endDate },
    });

    // Top destination
    const topDestinationAgg = await Booking.aggregate([
      { $match: { createdAt: { $gte: startDate, $lte: endDate } } },
      { $group: { _id: "$destination", count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 1 },
    ]);
    const topDestination = topDestinationAgg[0]?._id || "N/A";

    // Previous month (for growth)
    const prevMonth = selectedMonth === 0 ? 11 : selectedMonth - 1;
    const prevYear = selectedMonth === 0 ? selectedYear - 1 : selectedYear;
    const prevStart = startOfMonth(prevYear, prevMonth);
    const prevEnd = endOfMonth(prevYear, prevMonth);

    const prevBookings = await Booking.countDocuments({
      createdAt: { $gte: prevStart, $lte: prevEnd },
    });

    const growth =
      prevBookings > 0 ? ((total - prevBookings) / prevBookings) * 100 : total > 0 ? 100 : 0;

    res.json({
      type: "weekly",
      total,
      newUsers,
      growth: growth.toFixed(1),
      topDestination,
    });
  } catch (err) {
    console.error("❌ Weekly insights error:", err);
    res.status(500).json({ error: "Failed to load weekly insights" });
  }
});

// ===================================================
// 📅 MONTHLY INSIGHTS (based on selected year)
// ===================================================
router.get("/monthly", async (req, res) => {
  try {
    const now = new Date();
    const selectedYear = req.query.year ? parseInt(req.query.year) : now.getFullYear();

    const startDate = startOfYear(selectedYear);
    const endDate = endOfYear(selectedYear);

    const bookings = await Booking.find({
      createdAt: { $gte: startDate, $lte: endDate },
    });

    const totalBookings = bookings.length;
    const totalRevenue = bookings.reduce((sum, b) => sum + (b.totalAmount || 0), 0);

    // Compare to last year
    const lastYearStart = startOfYear(selectedYear - 1);
    const lastYearEnd = endOfYear(selectedYear - 1);

    const lastYearBookings = await Booking.find({
      createdAt: { $gte: lastYearStart, $lte: lastYearEnd },
    });

    const lastYearRevenue = lastYearBookings.reduce(
      (sum, b) => sum + (b.totalAmount || 0),
      0
    );

    const revenueGrowth =
      lastYearRevenue > 0
        ? ((totalRevenue - lastYearRevenue) / lastYearRevenue) * 100
        : totalRevenue > 0
        ? 100
        : 0;

    // Most used payment method
    const topPaymentAgg = await Booking.aggregate([
      { $match: { createdAt: { $gte: startDate, $lte: endDate } } },
      { $group: { _id: "$paymentMethod", count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 1 },
    ]);
    const topPayment = topPaymentAgg[0]?._id || "N/A";

    res.json({
      type: "monthly",
      totalBookings,
      totalRevenue: totalRevenue.toFixed(2),
      revenueGrowth: revenueGrowth.toFixed(1),
      topPayment,
    });
  } catch (err) {
    console.error("❌ Monthly insights error:", err);
    res.status(500).json({ error: "Failed to load monthly insights" });
  }
});

// ===================================================
// 📆 YEARLY INSIGHTS (based on selected start & end)
// ===================================================
router.get("/yearly", async (req, res) => {
  try {
    const now = new Date();
    const startYear = req.query.startYear ? parseInt(req.query.startYear) : now.getFullYear() - 3;
    const endYear = req.query.endYear ? parseInt(req.query.endYear) : now.getFullYear();

    const startDate = startOfYear(startYear);
    const endDate = endOfYear(endYear);

    const bookings = await Booking.find({
      createdAt: { $gte: startDate, $lte: endDate },
    });

    const totalBookings = bookings.length;
    const totalRevenue = bookings.reduce((sum, b) => sum + (b.totalAmount || 0), 0);

    // Calculate revenue per year
    const yearlyAgg = await Booking.aggregate([
      { $match: { createdAt: { $gte: startDate, $lte: endDate } } },
      {
        $group: {
          _id: { $year: "$createdAt" },
          totalRevenue: { $sum: "$totalAmount" },
          bookings: { $sum: 1 },
        },
      },
      { $sort: { _id: 1 } },
    ]);

    const revenueByYear = yearlyAgg.map((r) => ({
      year: r._id,
      revenue: r.totalRevenue,
      bookings: r.bookings,
    }));

    // Top 3 destinations
    const topDestinationsAgg = await Booking.aggregate([
      { $match: { createdAt: { $gte: startDate, $lte: endDate } } },
      { $group: { _id: "$destination", count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 3 },
    ]);

    res.json({
      type: "yearly",
      totalBookings,
      totalRevenue: totalRevenue.toFixed(2),
      revenueByYear,
      topDestinations: topDestinationsAgg.map((d) => d._id),
    });
  } catch (err) {
    console.error("❌ Yearly insights error:", err);
    res.status(500).json({ error: "Failed to load yearly insights" });
  }
});

module.exports = router;
