const mongoose = require('mongoose');

const tourSchema = new mongoose.Schema({
    title: {
        type: String,
        required: true,
        trim: true
    },
    description: {
        type: String,
        required: true
    },
    destination: {
        type: String,
        required: true
    },
    country: {
        type: String,
        required: true
    },
    price: {
        type: Number,
        required: true
    },
    duration: {
        type: Number,
        required: true,
        min: 1
    },
    durationUnit: {
        type: String,
        enum: ['days', 'weeks'],
        default: 'days'
    },
    imageUrl: {
        type: String,
        required: true
    },
    highlights: [{
        type: String
    }],
    inclusions: [{
        type: String
    }],
    exclusions: [{
        type: String
    }],
    hidden: { 
        type: Boolean, 
        default: false 
    },
    itinerary: [{
        day: Number,
        title: String,
        description: String
    }],
    featured: {
        type: Boolean,
        default: false
    },

    // ✈️ NEW: Travel Requirements Section
    requirements: {
        visaRequired: { type: Boolean, default: false },
        passportRequired: { type: Boolean, default: true },
        passportValidityMonths: { type: Number, default: 6 },
        travelInsuranceRequired: { type: Boolean, default: false },
        vaccinationRequired: { type: Boolean, default: false },
        otherRequirements: { type: String, trim: true, default: '' }
    },

    // 🏷️ Promo-related fields
    promoDuration: {
        type: Number,
        default: null // Duration in days for the promo
    },
    promoStartTime: {
        type: Date,
        default: null // Specific start time in Philippine time
    },
    promoEndTime: {
        type: Date,
        default: null // Calculated end time
    },
    isPromoActive: {
        type: Boolean,
        default: false
    },

    createdBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Admin',
        required: true
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    updatedAt: {
        type: Date,
        default: Date.now
    }
});

const Tour = mongoose.model('Tour', tourSchema);

module.exports = Tour;
