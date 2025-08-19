const mongoose = require('mongoose');

const pageViewSchema = new mongoose.Schema({
    path: {
        type: String,
        required: true
    },
    clientId: {
        type: String,
        required: true
    },
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        default: null
    },
    timestamp: {
        type: Date,
        default: Date.now
    }
});

module.exports = mongoose.model('PageView', pageViewSchema);
