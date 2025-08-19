// Create a model for SMS queue (add to your models folder)
const mongoose = require('mongoose');

const SMSQueueSchema = new mongoose.Schema({
    phone: {
        type: String,
        required: true
    },
    message: {
        type: String,
        required: true
    },
    attempts: {
        type: Number,
        default: 0
    },
    status: {
        type: String,
        enum: ['pending', 'sent', 'failed'],
        default: 'pending'
    },
    lastAttempt: Date,
    lastError: String,
    createdAt: {
        type: Date,
        default: Date.now
    }
});

const SMSQueue = mongoose.model('SMSQueue', SMSQueueSchema);
module.exports = SMSQueue;
