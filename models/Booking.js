const { citySeasons, countrySeasons } = require('../config/seasons');
const mongoose = require("mongoose");
const DailyBookingCount = require("./DailyBookingCount");

const statusChangeSchema = new mongoose.Schema({
    status: { type: String, required: true },
    updatedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin', required: true },
    updatedAt: { type: Date, default: Date.now }
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
    budget: { type: String, required: true },
    startDate: { type: Date, required: true },
    endDate: { type: Date, required: true },
    createdAt: { type: Date, default: Date.now },
    travelers: { type: Number },
    approvalStatus: { type: String, enum: ["Pending", "Approved", "Declined"], default: "Pending" },
    paymentMethod: { type: String, enum: ["paypal", "gcash", "store"], required: true },
    paymentId: { type: String },
    receiptUrl: { type: String },
    totalAmount: { type: Number, required: true },
    status: { type: String, enum: ["pending", "confirmed", "cancelled", "completed"], default: "pending" },
    archived: { type: Boolean, default: false },
    confirmedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
    completedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
    cancelledBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
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
        price: { type: Number }
    },
    expiresAt: { type: Date }
});

// Pre-save middleware
bookingSchema.pre("save", async function (next) {
    const isNew = this.isNew;

    // Generate booking ID on create
    if (isNew && !this.bookingId) {
        const date = new Date();
        const year = date.getFullYear().toString().slice(-2);
        const month = (date.getMonth() + 1).toString().padStart(2, '0');
        const day = date.getDate().toString().padStart(2, '0');
        const random = Math.floor(Math.random() * 10000).toString().padStart(4, '0');
        this.bookingId = `ABEE-${year}${month}${day}-${random}`;
    }

    // Handle store payment expiry
    if (isNew && this.paymentMethod === 'store' && !this.expiresAt) {
        const expiryDate = new Date();
        expiryDate.setHours(expiryDate.getHours() + 8);
        this.expiresAt = expiryDate;
    }

    // Season logic
    const month = this.startDate.getMonth() + 1;
    const destination = this.destination;
    const country = this.country;
    let seasons;

    if (citySeasons[destination]) {
        seasons = citySeasons[destination].seasons;
    } else if (country && countrySeasons[country]) {
        seasons = countrySeasons[country];
    } else {
        seasons = ['Winter', 'Spring', 'Summer', 'Fall'];
    }

    let season = 'Unknown';
    if (seasons.includes('Winter') && (month === 12 || month === 1 || month === 2)) {
        season = 'Winter';
    } else if (seasons.includes('Spring') && (month >= 3 && month <= 5)) {
        season = 'Spring';
    } else if (seasons.includes('Summer') && (month >= 6 && month <= 8)) {
        season = 'Summer';
    } else if (seasons.includes('Fall') && (month >= 9 && month <= 11)) {
        season = 'Fall';
    } else if (seasons.includes('Wet Season') && (month >= 5 && month <= 10)) {
        season = 'Wet Season';
    } else if (seasons.includes('Dry Season') && (month === 11 || month === 12 || month <= 4)) {
        season = 'Dry Season';
    } else if (seasons.includes('Monsoon') && (month >= 6 && month <= 9)) {
        season = 'Monsoon';
    } else if (seasons.includes('Post-Monsoon') && (month >= 10 && month <= 12)) {
        season = 'Post-Monsoon';
    }

    this.season = season;
    if (this.tourDetails) {
        this.tourDetails.season = season;
    }

    // Auto-set timestamps on status change
    if (!isNew && this.isModified('status')) {
        const now = new Date();
        switch (this.status) {
            case 'confirmed':
                if (!this.confirmedAt) this.confirmedAt = now;
                break;
            case 'completed':
                if (!this.completedAt) this.completedAt = now;
                break;
            case 'cancelled':
                if (!this.cancelledAt) this.cancelledAt = now;
                break;
        }
    }

    next();
});

// Post-save: track daily bookings
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

        console.log("Booking saved and daily count updated");
    } catch (error) {
        console.error("Error updating daily booking count:", error);
    }
});

module.exports = mongoose.model("Booking", bookingSchema);
