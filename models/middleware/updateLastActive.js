// middleware/updateLastActive.js
const User = require("../models/User");

module.exports = async function updateLastActive(req, res, next) {
  try {
    // Only run if user is logged in and session has their ID
    if (req.session && req.session.user && req.session.user.id) {
      await User.findByIdAndUpdate(req.session.user.id, {
        lastActiveAt: new Date(),
      });
    }
  } catch (err) {
    console.error("⚠️ Failed to update lastActiveAt:", err.message);
  }
  next(); // continue with the request
};
