// models/Contact.js
const mongoose = require('mongoose');

const contactSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true },
    phone: { type: String },
    country: { type: String},
    subject: { type: String, required: true },
    message: { type: String, required: true },
    status: { 
        type: String, 
        enum: ['unread', 'read', 'responded'], 
        default: 'unread' 
    },
    archived: { type: Boolean, default: false },
    displayOnHome: { type: Boolean, default: false },
    date: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Contact', contactSchema);
