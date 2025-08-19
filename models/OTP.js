const mongoose = require("mongoose");

const OTPSchema = new mongoose.Schema({
    email: { 
        type: String, 
        required: true,
        index: true
    },
    otp: { 
        type: String, 
        required: true 
    },
    expiresAt: { 
        type: Date, 
        required: true 
    },
    createdAt: { 
        type: Date, 
        default: Date.now
    },
    purpose: {
        type: String,
        enum: ['password_reset', 'email_verification', 'login_verification', 'other'],
        default: 'password_reset'
    }    
}, {
    timestamps: true
});

OTPSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

OTPSchema.index({ email: 1, otp: 1 });

module.exports = mongoose.model("OTP", OTPSchema);
