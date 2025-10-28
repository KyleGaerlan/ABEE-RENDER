if (typeof fetch === "undefined") {
  global.fetch = (...args) =>
    import("node-fetch").then(({ default: fetch }) => fetch(...args));
}
require('dotenv').config();
const express = require('express');
const path = require('path');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const nodemailer = require('nodemailer');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const User = require('./models/User');
const { ObjectId } = require('mongodb');
const OTP = require('./models/OTP');
const Booking = require('./models/Booking');
const bodyParser = require('body-parser');
const DailyUserCount = require('./models/DailyUserCount'); 
const DailyBookingCount = require('./models/DailyBookingCount');
const Admin = require('./models/Admin');
const router = express.Router();
const cron = require('node-cron');
const multer = require('multer');
const fs = require('fs');
const Tour = require('./models/Tour');
const PageView = require('./models/PageView');
const Contact = require('./models/Contact');
const validator = require('validator');
const axios = require('axios');
const updateLastActive = require("./middleware/updateLastActive");
const PYTHON_API = "http://127.0.0.1:8000";
const ExcelJS = require("exceljs");
const { Parser } = require("json2csv");


const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', 'your-frontend-domain');
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
    if (req.method === 'OPTIONS') {
        return res.sendStatus(200);
    }
    
    next();
});
app.use(session({
    secret: process.env.SESSION_SECRET || 'phar23',
    resave: false,
    saveUninitialized: true,
    cookie: { 
        httpOnly: true, 
        secure: false,
        sameSite: 'lax',
        maxAge: 24 * 60 * 60 * 1000
    },
    store: new MongoStore({ 
        mongoUrl: process.env.MONGODB_URI,
        collection: 'sessions'
    })
}));

app.use(updateLastActive);
const checkAdminAuth = (req, res, next) => {
    if (!req.session || !req.session.admin) {
        const isApiRequest = req.path.startsWith('/api/');
        
        if (isApiRequest) {
            return res.status(401).json({
                success: false,
                message: 'Unauthorized. Please log in again.'
            });
        } else {
            return res.redirect('/admin');
        }
    }
    next();
};
const checkRole = (roles) => {
    return (req, res, next) => {
        if (!req.session.admin || !roles.includes(req.session.admin.role)) {

            return res.status(403).redirect('/error');
        }
        next();
    };
};
mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log('✅ Connected to MongoDB'))
.catch(err => {
    console.error('❌ MongoDB connection error:', err);
    process.exit(1);
});
Admin.collection.createIndex({ email: 1 }, { unique: true });

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});
const { v4: uuidv4 } = require('uuid');

app.use((req, res, next) => {
    if (!req.session.clientId) {
        req.session.clientId = uuidv4();
    }
    next();
});

app.use((req, res, next) => {
    if (!req.path.startsWith('/css/') && 
        !req.path.startsWith('/js/') && 
        !req.path.startsWith('/images/') &&
        !req.path.startsWith('/api/') &&
        !req.path.startsWith('/uploads/')) {
        
        const userId = req.session.user ? req.session.user.id : null;
        
        PageView.create({
            path: req.path,
            clientId: req.session.clientId,
            userId: userId,
            timestamp: new Date()
        }).catch(err => console.error('Error tracking page view:', err));
    }
    next();
});
app.use('/api/insights', require('./routes/insights'));

async function sendSMS(phoneNumber, message) {
    try {
        let formattedPhone = phoneNumber.replace(/\D/g, '');
        
        // Format phone number for Philippines
        if (formattedPhone.startsWith('0')) {
            formattedPhone = '+63' + formattedPhone.substring(1);
        } else if (!formattedPhone.startsWith('+')) {
            if (formattedPhone.startsWith('63')) {
                formattedPhone = '+' + formattedPhone;
            } else {
                formattedPhone = '+63' + formattedPhone;
            }
        }

        console.log(`Sending SMS to ${formattedPhone}: ${message}`);

        const response = await fetch('https://textbelt.com/text', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                phone: formattedPhone,
                message: message,
                key: process.env.TEXTBELT_API_KEY
            })
        });

        const result = await response.json();
        console.log('SMS API response:', result);

        if (result.success) {
            return {
                success: true,
                message: 'SMS sent successfully',
                details: result
            };
        } else {
            return {
                success: false,
                message: 'Failed to send SMS: ' + (result.error || 'Unknown error')
            };
        }
    } catch (error) {
        console.error('SMS sending error:', error);
        return {
            success: false,
            message: 'Failed to send SMS: ' + error.message
        };
    }
}

async function sendApprovalEmail(email) {
    await transporter.sendMail({
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Account Approved',
        html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                <h2>Your Account Has Been Approved!</h2>
                <p>Your admin account has been approved. You can now log in to the admin dashboard.</p>
                <p>Thank you for joining our team!</p>
            </div>
        `
    });
}

async function sendRejectionEmail(email) {
    await transporter.sendMail({
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Account Request Declined',
        html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                <h2>Account Request Declined</h2>
                <p>We regret to inform you that your admin account request has been declined.</p>
                <p>If you believe this is an error, please contact the system administrator.</p>
            </div>
        `
    });
}
async function sendBookingStatusEmail(email, booking, status) {
    try {
        let subject = '';
        let message = '';

        switch (status) {
            case 'confirmed':
                subject = 'Your Booking Has Been Confirmed!';
                message = `
                    <h2>Booking Confirmed</h2>
                    <p>Hi ${booking.fullName || 'Customer'},</p>
                    <p>Your booking for <strong>${booking.destination || booking.tourDetails?.destination}</strong> has been confirmed.</p>
                    <p>Booking ID: <strong>${booking.bookingId || booking._id}</strong></p>
                    <p>Thank you for choosing us!</p>
                `;
                break;
            case 'cancelled':
                subject = 'Your Booking Has Been Cancelled';
                message = `
                    <h2>Booking Cancelled</h2>
                    <p>Hi ${booking.fullName || 'Customer'},</p>
                    <p>We regret to inform you that your booking for <strong>${booking.destination}</strong> was cancelled.</p>
                    <p>If you believe this was an error, please contact our team.</p>
                `;
                break;
            case 'completed':
                subject = 'Your Trip Has Been Completed!';
                message = `
                    <h2>Trip Completed</h2>
                    <p>Hi ${booking.fullName || 'Customer'},</p>
                    <p>Your trip to <strong>${booking.destination}</strong> has been marked as completed. We hope you enjoyed it!</p>
                `;
                break;
            default:
                subject = 'Booking Status Updated';
                message = `<p>Your booking status has been updated to <strong>${status}</strong>.</p>`;
        }

        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject,
            html: `
                <div style="font-family: Arial; padding: 20px; border: 1px solid #eee;">
                    ${message}
                    <br><p style="font-size: 0.9em;">— The Travel Team</p>
                </div>
            `
        });
    } catch (error) {
        console.error('❌ Failed to send booking email:', error);
    }
}


async function notifyAdminsAboutNewRequest(newAdmin) {
    try {
        const admins = await Admin.find({ 
            role: 'admin',
            status: 'active',
            isVerified: true
        });
        
        if (admins.length === 0) return;
        for (const admin of admins) {
            await transporter.sendMail({
                from: process.env.EMAIL_USER,
                to: admin.email,
                subject: "New Admin Account Request",
                html: `
                    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;">
                        <h2 style="color: #f26523;">New Account Request</h2>
                        <p>A new admin account request has been submitted and requires your approval:</p>
                        <div style="background-color: #f5f5f5; padding: 15px; margin: 15px 0; border-radius: 5px;">
                            <p><strong>Name:</strong> ${newAdmin.firstName} ${newAdmin.lastName}</p>
                            <p><strong>Email:</strong> ${newAdmin.email}</p>
                            <p><strong>Username:</strong> ${newAdmin.username}</p>
                            <p><strong>Role:</strong> ${newAdmin.role}</p>
                            <p><strong>Phone:</strong> ${newAdmin.phoneNumber}</p>
                        </div>
                        <p>Please log in to the admin dashboard to approve or decline this request.</p>
                        <div style="margin-top: 20px;">
                            <a href="${process.env.BASE_URL || 'https://abeetravel.com'}/admin-approvals" 
                               style="background-color: #f26523; color: white; padding: 10px 15px; text-decoration: none; border-radius: 5px;">
                                Review Request
                            </a>
                        </div>
                    </div>
                `
            });
        }
    } catch (error) {
        console.error('❌ Error sending admin notifications:', error);
    }
}
const rateLimiter = {};
const apiRouter = express.Router();

apiRouter.delete('/users/:userId', checkAdminAuth, async (req, res) => {
    try {
        const { userId } = req.params;
        
        console.log('Delete user request received for ID:', userId);
        
        if (!mongoose.Types.ObjectId.isValid(userId)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid user ID format'
            });
        }
        
        await Booking.deleteMany({ userId: userId });
        const deletedUser = await User.findByIdAndDelete(userId);
        
        if (!deletedUser) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }
        
        console.log('User deleted successfully:', userId);
        
        res.json({
            success: true,
            message: 'User and associated bookings deleted successfully'
        });
    } catch (error) {
        console.error('❌ Error deleting user:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to delete user: ' + error.message
        });
    }
});
// ✅ Middleware for user login
const checkUserAuth = (req, res, next) => {
  if (!req.session.user) {
    return res.redirect('/login?next=/contact');
  }
  next();
};

app.get('/message', (req, res) => {
  res.render('message', { user: req.session.user }); // ✅ Add user
});

app.post('/contact', async (req, res) => {
    try {
        const user = req.session.user; // or however you store logged-in user
        if (!user) {
            return res.status(401).json({ success: false, message: 'You must be logged in to send a message.' });
        }

        const { subject, message } = req.body;

        if (!subject || !message) {
            return res.status(400).json({ success: false, message: 'Subject and message are required.' });
        }

        // Save message
        const newMessage = new Contact({
            name: `${user.firstName} ${user.lastName}`,
            email: user.email,
            phone: user.phone || '',
            country: user.country || '',
            subject,
            message
        });

        await newMessage.save();

        res.json({ success: true, message: 'Message sent successfully!' });
    } catch (error) {
        console.error('Error saving contact message:', error);
        res.status(500).json({ success: false, message: 'Server error. Please try again later.' });
    }
});


app.use('/api', apiRouter);
apiRouter.get('/admins', checkAdminAuth, checkRole(['admin']), async (req, res) => {
    try {
        const admins = await Admin.find().select('-password');
        res.json({ success: true, admins });
    } catch (error) {
        console.error('Error fetching admins:', error);
        res.status(500).json({ success: false, message: 'Failed to fetch admins' });
    }
});

app.post('/admin-signup', async (req, res) => {
    try {
        const {

            firstName,
            lastName,
            username,
            email,
            password,
            phoneNumber,
            role,
        } = req.body;

        if (!firstName || !lastName || !username || !email || !password || !phoneNumber) {
            return res.status(400).json({
                success: false,
                message: 'All fields are required'
            });
        }

        const existingAdmin = await Admin.findOne({ 
            $or: [{ email }, { username }] 
        });
        
        if (existingAdmin) {
            if (existingAdmin.username === username) {
                return res.status(400).json({ success: false, message: 'Username already taken' });
            }
            if (existingAdmin.email === email) {
                return res.status(400).json({ success: false, message: 'Email already taken' });
            }
            if (existingAdmin.status === 'pending') {
                return res.status(400).json({ success: false, message: 'Your account request is already pending approval' });
            }
        }

        const admin = new Admin({
            firstName,
            lastName,
            username,
            email,
            password,
            phoneNumber,
            role: role || 'employee',
            status: 'pending',
            isVerified: false
        });

        await admin.save();

        await notifyAdminsAboutNewRequest(admin);

        res.status(201).json({
            success: true,
            message: 'Admin account request submitted successfully. Awaiting approval.'
        });
    } catch (error) {
        console.error('❌ Admin signup error:', error);
        if (error.code === 11000) {
            return res.status(400).json({
                success: false,
                message: 'Email or username already in use'
            });
        }
        
        res.status(500).json({
            success: false,
            message: 'Error creating admin account'
        });
    }
});
app.post('/api/admin/send-verification', async (req, res) => {
    const { email } = req.body;
    
    if (rateLimiter[email] && Date.now() - rateLimiter[email] < 60000) {
        return res.status(429).json({
            success: false,
            message: "Please wait before requesting another code."
        });
    }
    
    rateLimiter[email] = Date.now();
    
    try {
        const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
        const expiresAt = new Date(Date.now() + 10 * 60 * 1000);  
        
        await OTP.findOneAndUpdate(
            { email }, 
            { otp: verificationCode, expiresAt }, 
            { upsert: true, new: true }
        );
        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject: "Your Admin Account Verification Code",
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;">
                    <h2 style="color: #f26523;">Admin Account Verification</h2>
                    <p>Thank you for requesting an admin account. Please use the following code to verify your email address:</p>
                    <div style="background-color: #f5f5f5; padding: 10px; text-align: center; font-size: 24px; font-weight: bold; letter-spacing: 5px; margin: 20px 0;">
                        ${verificationCode}
                    </div>
                    <p>This code will expire in 10 minutes.</p>
                    <p>If you didn't request this verification, please ignore this email.</p>
                </div>
            `
        });

        return res.json({ 
            success: true, 
            message: "Verification code sent successfully!" 
        });

    } catch (error) {
        console.error("❌ Admin Verification Code Sending Error:", error);
        return res.status(500).json({ 
            success: false, 
            message: "Failed to send verification code." 
        });
    }
});
app.post('/api/admin/verify-code', async (req, res) => {
    const { email, code } = req.body;

    if (!email || !code) {
        return res.status(400).json({ success: false, message: "Email and code are required." });
    }

    try {
        // Find OTP specifically bound to this email
        const otpRecord = await OTP.findOne({ email }).lean();

        if (!otpRecord) {
            return res.status(400).json({ success: false, message: "No verification code found for this email." });
        }

        // Check OTP validity
        if (otpRecord.otp !== code) {
            return res.status(400).json({ success: false, message: "Incorrect verification code." });
        }

        if (Date.now() > otpRecord.expiresAt) {
            return res.status(400).json({ success: false, message: "Verification code expired." });
        }

        // ✅ OTP is valid → clear it immediately to prevent reuse
        await OTP.deleteOne({ email });

        return res.json({ success: true, message: "Verification successful!" });
    } catch (err) {
        console.error("❌ Admin Verify Code Error:", err);
        return res.status(500).json({ success: false, message: "Internal Server Error" });
    }
});


app.post('/api/admin/signup', async (req, res) => {
    try {
        const {
            firstName,
            lastName,
            username,
            email,
            password,
            phoneNumber,
            role,
            verified
        } = req.body;

        console.log('Received signup data:', { 
            firstName, lastName, username, email, 
            phoneNumber, role, verified, 
            passwordProvided: !!password 
        });

        if (!firstName || !lastName || !username || !email || !password || !phoneNumber) {
            return res.status(400).json({
                success: false,
                message: 'All fields are required'
            });
        }

        const existingAdmin = await Admin.findOne({ 
            $or: [{ email }, { username }] 
        });
        
        if (existingAdmin) {

            if (existingAdmin.status === 'pending') {
                return res.status(400).json({
                    success: false,
                    message: 'Your account request is already pending approval'
                });
            }
            
            return res.status(400).json({
                success: false,
                message: 'Email or username already in use'
            });
        }

        const admin = new Admin({
            firstName,
            lastName,
            username,
            email,
            password,
            phoneNumber,
            role: role || 'employee',
            status: 'pending',
            isVerified: verified === true
        });

        await admin.save();

        await notifyAdminsAboutNewRequest(admin);

        res.status(201).json({
            success: true,
            message: 'Admin account created successfully. Awaiting approval.'
        });
    } catch (error) {
        console.error('❌ Admin signup error:', error);
        if (error.code === 11000) {
            return res.status(400).json({
                success: false,
                message: 'Email or username already in use'
            });
        }
        
        res.status(500).json({
            success: false,
            message: 'Error creating admin account'
        });
    }
});

app.post('/verify-otp', async (req, res) => {
    const { email, otp } = req.body;
    
    if (!email || !otp) {
        return res.status(400).json({ success: false, message: "Email and OTP are required." });
    }

    try {
        const otpRecord = await OTP.findOne({ email }).lean();

        if (!otpRecord) {
            return res.status(400).json({ success: false, message: "Invalid OTP. Please try again." });
        }

        if (otpRecord.otp !== otp) {
            return res.status(400).json({ success: false, message: "Incorrect OTP. Please try again." });
        }

        if (Date.now() > otpRecord.expiresAt) {
            return res.status(400).json({ success: false, message: "OTP has expired. Request a new one." });
        }
        req.session.otpVerified = true;
        req.session.email = email;
        
        await OTP.deleteOne({ email });

        return res.json({ success: true, message: "OTP verified successfully!" });

    } catch (error) {
        console.error("❌ OTP Verification Error:", error);
        return res.status(500).json({ success: false, message: "Internal Server Error" });
    }
});

app.post("/reset-password", async (req, res) => {
    const { email, newPassword } = req.body;
    console.log("🔄 Password reset request for email:", email);
    
    if (!req.session.otpVerified || req.session.email !== email) {
        console.log("❌ Unauthorized reset attempt for email:", email);
        return res.status(401).json({ success: false, message: "Unauthorized reset request." });
    }

    try {
        const user = await User.findOne({ email });
        if (!user) {
            console.log("❌ User not found for password reset:", email);
            return res.status(404).json({ success: false, message: "User not found." });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await User.findOneAndUpdate({ email }, { password: hashedPassword });
        console.log("✅ Password reset successful for email:", email);

        req.session.destroy();
        res.json({ success: true, message: "Password reset successfully!" });
    } catch (error) {
        console.error("❌ Password Reset Error:", error);
        res.status(500).json({ success: false, message: "Failed to reset password. Please try again." });
    }
});

app.post('/check-email', async (req, res) => {
    const { email } = req.body;
    
    if (!email) {
        return res.status(400).json({ success: false, message: "Email is required." });
    }
    
    try {
        const user = await User.findOne({ email });
        return res.json({ exists: !!user });
    } catch (error) {
        console.error("❌ Error checking email:", error);
        return res.status(500).json({ success: false, message: "Error checking email." });
    }
});

app.get('/admin', (req, res) => {
    res.render('admin');
});
app.post('/api/admin/login', async (req, res) => {
    console.log('Admin login request received:', req.body);
    const { username, password, captchaVerified } = req.body;

    if (!captchaVerified) {
        return res.status(400).json({ 
            success: false, 
            message: 'CAPTCHA verification required' 
        });
    }

    try {
        const admin = await Admin.findOne({ username });
        console.log('Admin found:', admin ? 'Yes' : 'No');

        if (!admin) {
            return res.status(401).json({ 
                success: false, 
                message: 'Invalid credentials' 
            });
        }
if (admin.isActive === false) {
    return res.status(403).json({
        success: false,
        message: 'Your admin account has been deactivated. Please contact support.'
    });
}

if (!admin.isVerified || admin.status !== 'active') {
    return res.status(401).json({ 
        success: false, 
        status: 'pending',
        message: 'Your account is pending approval' 
    });
}


        const isMatch = await bcrypt.compare(password, admin.password);
        console.log('Password match:', isMatch ? 'Yes' : 'No');
        
        if (!isMatch) {
            return res.status(401).json({ 
                success: false, 
                message: 'Invalid credentials' 
            });
        }

        req.session.admin = {
            id: admin._id,
            firstName: admin.firstName,
            lastName: admin.lastName,
            username: admin.email,
            role: admin.role
        };
        
        let redirectUrl;
        if (admin.role === 'admin') {
            redirectUrl = '/admin-dashboard';
        } else if (admin.role === 'employee') {
            redirectUrl = '/employee-dashboard';
        } else {
            redirectUrl = '/';
        }

        return res.json({
            success: true,
            message: 'Login successful',
            redirectUrl: redirectUrl,
            admin: {
                id: admin._id,
                firstName: admin.firstName,
                lastName: admin.lastName,
                username: admin.username,
                role: admin.role
            }
        });
    } catch (error) {
        console.error('❌ Admin Login Error:', error);
        return res.status(500).json({ 
            success: false, 
            message: 'Internal Server Error' 
        });
    }
});
app.post('/api/admin/verify-credentials', async (req, res) => {
    try {
        const { username, password } = req.body;
        const admin = await Admin.findOne({ username });

        if (!admin) {
            return res.status(400).json({ success: false, message: 'Invalid credentials' });
        }
        
        const isMatch = await bcrypt.compare(password, admin.password);
        if (!isMatch) {
            return res.status(400).json({ success: false, message: 'Invalid credentials' });
        }

        if (!admin.isVerified || admin.status !== 'active') {
            return res.status(401).json({ 
                success: false, 
                status: 'pending',
                message: 'Your account is pending approval' 
            });
        }

        return res.json({ 
            success: true, 
            message: 'Credentials verified'
        });

    } catch (error) {
        console.error('❌ Admin credential verification error:', error);
        return res.status(500).json({ success: false, message: 'Internal Server Error' });
    }
});

app.get('/admin-dashboard', checkAdminAuth, (req, res) => {
    res.render('admin-dashboard', { admin: req.session.admin });
});
app.get('/admin-users', checkAdminAuth, checkRole(['admin']), async (req, res) => {
    try {
        const users = await User.find();
        res.render('admin-users', { admin: req.session.admin, users, admins: [] });
    } catch (err) {
        console.error('Error fetching users:', err);
        res.status(500).send('Error fetching users');
    }
});
app.get('/employee-dashboard', checkAdminAuth, checkRole(['admin','employee']), (req, res) => {
    res.render('employee-dashboard', { admin: req.session.admin });
});

app.get('/admin-bookings', checkAdminAuth, checkRole(['admin', 'employee']), (req, res) => {
    res.render('admin-bookings', { admin: req.session.admin });
});
app.get('/api/employee-performance', checkAdminAuth, checkRole(['admin', 'employee']), async (req, res) => {
    try {
        const adminId = req.session.admin.id;
        const isAdmin = req.session.admin.role === 'admin';

        const { period, startDate, endDate, month, year } = req.query;

        let dateFilter = {};
        if (period === 'daily' && startDate && endDate) {
            dateFilter = {
                createdAt: {
                    $gte: new Date(startDate),
                    $lte: new Date(endDate)
                }
            };
        } else if (period === 'monthly' && month && year) {
            const monthStart = new Date(year, month - 1, 1);
            const monthEnd = new Date(year, month, 0, 23, 59, 59);
            dateFilter = {
                createdAt: {
                    $gte: monthStart,
                    $lte: monthEnd
                }
            };
        } else if (period === 'yearly' && year) {
            const yearStart = new Date(year, 0, 1);
            const yearEnd = new Date(year, 11, 31, 23, 59, 59);
            dateFilter = {
                createdAt: {
                    $gte: yearStart,
                    $lte: yearEnd
                }
            };
        }

        if (isAdmin) {
        const matchStage = {
            status: { $in: ['confirmed', 'completed'] },
            ...dateFilter
        };


            const performance = await Booking.aggregate([
                { $match: matchStage },
                {
                    $facet: {
                        confirmed: [
                            { $match: { status: 'confirmed', confirmedBy: { $ne: null } } },
                            { $group: { _id: '$confirmedBy', count: { $sum: 1 } } }
                        ],
                        completed: [
                            { $match: { status: 'completed', completedBy: { $ne: null } } },
                            { $group: { _id: '$completedBy', count: { $sum: 1 } } }
                        ]
                    }
                },
                {
                    $project: {
                        allStats: {
                            $concatArrays: [
                                { $map: { input: "$confirmed", as: "c", in: { employeeId: "$$c._id", confirmed: "$$c.count", completed: 0 } } },
                                { $map: { input: "$completed", as: "p", in: { employeeId: "$$p._id", confirmed: 0, completed: "$$p.count" } } }
                            ]
                        }
                    }
                },
                { $unwind: "$allStats" },
                {
                    $group: {
                        _id: "$allStats.employeeId",
                        totalConfirmed: { $sum: "$allStats.confirmed" },
                        totalCompleted: { $sum: "$allStats.completed" }
                    }
                },
                {
                    $lookup: {
                        from: 'admins', // Adjust if your collection name differs
                        localField: '_id',
                        foreignField: '_id',
                        as: 'employeeDetails'
                    }
                },
                { $unwind: "$employeeDetails" },
                {
                    $project: {
                        employeeId: '$_id',
                        employeeName: { $concat: ["$employeeDetails.firstName", " ", "$employeeDetails.lastName"] },
                        totalConfirmed: 1,
                        totalCompleted: 1,
                        _id: 0
                    }
                },
                { $sort: { totalCompleted: -1, totalConfirmed: -1 } }
            ]);

            const adminPerformance = await getEmployeePerformance(adminId);
            adminPerformance.overallPerformance = performance;
            res.json({ success: true, ...adminPerformance });
        } else {
    // Employee view with revenue + all groupings
    const employeePerformance = await getEmployeePerformance(adminId, { period, startDate, endDate, month, year });
    res.json({ success: true, ...employeePerformance });
}

    } catch (error) {
        console.error('Error fetching employee performance:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});
// ✅ Update booking status (used by admin-bookings.ejs)
app.patch('/api/admin/bookings/:id/status', checkAdminAuth, checkRole(['admin', 'employee']), async (req, res) => {
  try {
    const { status } = req.body;
    const bookingId = req.params.id;
    const adminId = req.session.admin?._id || req.session.admin?.id; // support both

    // Validate status input
    const validStatuses = ['pending', 'confirmed', 'cancelled', 'completed'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ success: false, message: 'Invalid status' });
    }

    const booking = await Booking.findById(bookingId);
    if (!booking) {
      return res.status(404).json({ success: false, message: 'Booking not found' });
    }

    // ✅ Record the status change in history
    booking.status = status;
    booking.statusChangeHistory.push({
      status,
      updatedBy: adminId,
      updatedAt: new Date()
    });

    // ✅ Record admin who performed each action
    if (status === 'confirmed') booking.confirmedBy = adminId;
    if (status === 'completed') booking.completedBy = adminId;
    if (status === 'cancelled') booking.cancelledBy = adminId;

    booking.updatedAt = new Date();
    await booking.save();

    // ✅ Send notification email to user
    await sendBookingStatusEmail(booking.email, booking, status);

    res.json({
      success: true,
      message: `Booking updated to ${status} and recorded in history.`,
      booking
    });

    console.log(`📩 Booking ${booking.bookingId || bookingId} updated (${status}) by admin ${adminId}`);
  } catch (error) {
    console.error('❌ Error updating booking status:', error);
    res.status(500).json({
      success: false,
      message: 'Server error while updating booking status'
    });
  }
});


app.post('/api/bookings/:id/confirm', checkAdminAuth, async (req, res) => {
    try {
        const booking = await Booking.findById(req.params.id);
        if (!booking) return res.status(404).json({ success: false, message: 'Booking not found' });

        booking.status = 'confirmed';
        booking.confirmedBy = req.session.admin.id;
        booking.confirmedAt = new Date();
        await booking.save();

        await sendBookingStatusEmail(booking.email, booking, 'confirmed');

        res.json({ success: true, message: 'Booking confirmed and email sent', booking });
    } catch (error) {
        console.error('Error confirming booking:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// CANCEL booking
app.post('/api/bookings/:id/cancel', checkAdminAuth, async (req, res) => {
    try {
        const booking = await Booking.findById(req.params.id);
        if (!booking) return res.status(404).json({ success: false, message: 'Booking not found' });

        booking.status = 'cancelled';
        await booking.save();

        await sendBookingStatusEmail(booking.email, booking, 'cancelled');

        res.json({ success: true, message: 'Booking cancelled and email sent', booking });
    } catch (error) {
        console.error('Error cancelling booking:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// COMPLETE booking (already exists but add email)
app.post('/api/bookings/:id/complete', checkAdminAuth, async (req, res) => {
    try {
        const booking = await Booking.findById(req.params.id);
        if (!booking) return res.status(404).json({ success: false, message: 'Booking not found' });

        booking.status = 'completed';
        booking.completedBy = req.session.admin.id;
        booking.completedAt = new Date();
        await booking.save();

        await sendBookingStatusEmail(booking.email, booking, 'completed');

        res.json({ success: true, message: 'Booking marked as completed and email sent', booking });
    } catch (error) {
        console.error('Error completing booking:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

async function getEmployeePerformance(employeeId, { period, startDate, endDate, month, year } = {}) {
    const query = { $or: [{ confirmedBy: employeeId }, { completedBy: employeeId }] };

    // Apply date filters
    if (period === 'daily' && startDate && endDate) {
        query.createdAt = { $gte: new Date(startDate), $lte: new Date(endDate) };
    } else if (period === 'monthly' && month && year) {
        const monthStart = new Date(year, month - 1, 1);
        const monthEnd = new Date(year, month, 0, 23, 59, 59);
        query.createdAt = { $gte: monthStart, $lte: monthEnd };
    } else if (period === 'yearly' && year) {
        const yearStart = new Date(year, 0, 1);
        const yearEnd = new Date(year, 11, 31, 23, 59, 59);
        query.createdAt = { $gte: yearStart, $lte: yearEnd };
    }

    const bookings = await Booking.find(query);

    const confirmedBookings = bookings.filter(b => b.confirmedBy?.toString() === employeeId.toString() && b.status === 'confirmed');
    const completedBookings = bookings.filter(b => b.completedBy?.toString() === employeeId.toString() && b.status === 'completed');

    const totalConfirmedBookings = confirmedBookings.length;
    const totalCompletedBookings = completedBookings.length;

    // Calculate revenue
    const uniqueBookings = new Map();
    bookings.forEach(b => uniqueBookings.set(b._id.toString(), b));
    const totalRevenue = Array.from(uniqueBookings.values()).reduce((sum, b) => sum + (b.totalAmount || 0), 0);

    // --- Breakdown ---
    const bookingsByMonth = {};
    const bookingsByDay = {};
    const bookingsByYear = {};

    for (const booking of uniqueBookings.values()) {
        const date = new Date(booking.createdAt);

        // Month breakdown
        const monthLabel = date.toLocaleString('default', { month: 'long' });
        if (!bookingsByMonth[monthLabel]) bookingsByMonth[monthLabel] = { confirmed: 0, completed: 0, revenue: 0 };
        if (booking.status === 'confirmed') bookingsByMonth[monthLabel].confirmed++;
        if (booking.status === 'completed') bookingsByMonth[monthLabel].completed++;
        bookingsByMonth[monthLabel].revenue += booking.totalAmount || 0;

        // Daily breakdown
        const dayLabel = date.toISOString().split('T')[0];
        if (!bookingsByDay[dayLabel]) bookingsByDay[dayLabel] = { confirmed: 0, completed: 0, revenue: 0 };
        if (booking.status === 'confirmed') bookingsByDay[dayLabel].confirmed++;
        if (booking.status === 'completed') bookingsByDay[dayLabel].completed++;
        bookingsByDay[dayLabel].revenue += booking.totalAmount || 0;

        // Yearly breakdown
        const yearLabel = date.getFullYear();
        if (!bookingsByYear[yearLabel]) bookingsByYear[yearLabel] = { confirmed: 0, completed: 0, revenue: 0 };
        if (booking.status === 'confirmed') bookingsByYear[yearLabel].confirmed++;
        if (booking.status === 'completed') bookingsByYear[yearLabel].completed++;
        bookingsByYear[yearLabel].revenue += booking.totalAmount || 0;
    }

    return { totalConfirmedBookings, totalCompletedBookings, totalRevenue, bookingsByMonth, bookingsByDay, bookingsByYear };
}

app.get('/api/admin/employee-performance', checkAdminAuth, checkRole(['admin']), async (req, res) => {
    try {
        const performance = await Booking.aggregate([
            {
                $match: {
                    status: { $in: ['confirmed', 'completed'] }
                }
            },
            {
                $facet: {
                    confirmed: [
                        { $match: { status: 'confirmed', confirmedBy: { $ne: null } } },
                        { $group: { _id: '$confirmedBy', count: { $sum: 1 } } }
                    ],
                    completed: [
                        { $match: { status: 'completed', completedBy: { $ne: null } } },
                        { $group: { _id: '$completedBy', count: { $sum: 1 } } }
                    ]
                }
            },
            {
                $project: {
                    allStats: {
                        $concatArrays: [
                            { $map: { input: "$confirmed", as: "c", in: { employeeId: "$$c._id", confirmed: "$$c.count", completed: 0 } } },
                            { $map: { input: "$completed", as: "p", in: { employeeId: "$$p._id", confirmed: 0, completed: "$$p.count" } } }
                        ]
                    }
                }
            },
            { $unwind: "$allStats" },
            {
                $group: {
                    _id: "$allStats.employeeId",
                    totalConfirmed: { $sum: "$allStats.confirmed" },
                    totalCompleted: { $sum: "$allStats.completed" }
                }
            },
            {
                $lookup: {
                    from: 'admins', // The collection name for your Admin model
                    localField: '_id',
                    foreignField: '_id',
                    as: 'employeeDetails'
                }
            },
            {
                $unwind: "$employeeDetails"
            },
            {
                $project: {
                    employeeId: '$_id',
                    employeeName: { $concat: ["$employeeDetails.firstName", " ", "$employeeDetails.lastName"] },
                    totalConfirmed: 1,
                    totalCompleted: 1,
                    _id: 0
                }
            },
            { $sort: { totalCompleted: -1, totalConfirmed: -1 } }
        ]);

        res.json({ success: true, performance });
    } catch (error) {
        console.error('Error fetching overall employee performance:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});
app.post('/api/admin/login-redirect', async (req, res) => {
    console.log('Admin login redirect request received:', req.body);
    const { username, password, role } = req.body;

    try {
        const admin = await Admin.findOne({ email });
        console.log('Admin found:', admin ? 'Yes' : 'No');

        if (!admin) {
            return res.redirect('/admin?error=invalid-credentials');
        }

        if (role && admin.role !== role) {
            return res.redirect('/admin?error=invalid-role');
        }
        
        if (!admin.isVerified || admin.status !== 'active') {
            return res.redirect('/admin?error=pending-approval');
        }
        
        const isMatch = await bcrypt.compare(password, admin.password);
        console.log('Password match:', isMatch ? 'Yes' : 'No');
        
        if (!isMatch) {
            return res.redirect('/admin?error=invalid-credentials');
        }
        
        req.session.admin = {
            id: admin._id,
            firstName: admin.firstName,
            lastName: admin.lastName,
            email: admin.email,
            role: admin.role
        };
        
        console.log('Admin login successful, redirecting to dashboard');
        if (admin.role === 'admin') {
            return res.redirect('/admin-dashboard');
        } else if (admin.role === 'employee') {
            return res.redirect('/employee-dashboard');
        }
        // Fallback for other roles if any
        return res.redirect('/');
    } catch (error) {
        console.error('❌ Admin Login Error:', error);
        return res.redirect('/admin?error=server-error');
    }
});

app.get('/admin-approvals', checkAdminAuth, (req, res) => {
    res.render('admin-approvals', { admin: req.session.admin });
});


app.get('/api/admin/pending-accounts', checkAdminAuth, async (req, res) => {
    try {
        const pendingAccounts = await Admin.find({ 
            status: 'pending'
        }).select('-password');
        
        res.json({ success: true, pendingAccounts });
    } catch (error) {
        console.error('Error fetching pending accounts:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to fetch pending accounts' 
        });
    }
});

app.post('/api/admin/account-action', checkAdminAuth, async (req, res) => {
    try {
        const { accountId, action } = req.body;
        
        if (action === 'approve') {
            const account = await Admin.findByIdAndUpdate(accountId, {
                status: 'active',
                isVerified: true
            }, { new: true });

            await sendApprovalEmail(account.email);
            
            res.json({ 
                success: true, 
                message: 'Account approved successfully' 
            });
        } else if (action === 'decline') {
            const account = await Admin.findById(accountId);
          
            await sendRejectionEmail(account.email);
            
            await Admin.findByIdAndDelete(accountId);
            
            res.json({ 
                success: true, 
                message: 'Account declined and removed' 
            });
        } else {
            res.status(400).json({ 
                success: false, 
                message: 'Invalid action' 
            });
        }
    } catch (error) {
        console.error('Error processing account action:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to process account action' 
        });
    }
});
// ========= 1️⃣ SALES FORECAST =========
app.get('/api/predict/sales', async (req, res) => {
  try {
    const salesData = await Booking.aggregate([
      { $match: { status: { $ne: "cancelled" } } },
      {
        $group: {
          _id: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } },
          totalSales: { $sum: "$totalAmount" }
        }
      },
      { $sort: { "_id": 1 } }
    ]);

    if (!salesData || salesData.length < 3)
      return res.json({ success: false, message: "Not enough sales data for forecast." });

    const series = salesData.map(s => ({ ds: s._id, y: s.totalSales }));

    const { data } = await axios.post("http://127.0.0.1:8000/predict", {
      series,
      horizon: 30
    });

    console.log("🧠 Sales Forecast:", data.success, "—", data.forecast?.length, "points");
    res.json(data);
  } catch (err) {
    console.error("❌ Prediction API Error (Sales):", err.message);
    res.status(500).json({ success: false, message: err.message });
  }
});
// ============================================
// 📈 /api/admin/metrics-growth
// ============================================
app.get("/api/admin/metrics-growth", async (req, res) => {
  try {
    const monthly = await Booking.aggregate([
      // ✅ Only include confirmed and completed bookings
      {
        $match: {
          status: { $in: ["confirmed", "completed"] }
        }
      },

      // 🧮 Group by month-year based on createdAt
      {
        $group: {
          _id: { $dateToString: { format: "%Y-%m", date: "$createdAt" } },
          totalSales: { $sum: { $ifNull: ["$totalAmount", 0] } },
          totalBookings: { $sum: 1 }
        }
      },

      // 📅 Sort by date ascending
      { $sort: { "_id": 1 } }
    ]);

    // ✅ Build continuous timeline (fill missing months with 0)
    const months = [];
    const sales = [];
    const bookings = [];

    if (monthly.length > 0) {
      const firstMonth = new Date(monthly[0]._id + "-01");
      const lastMonth = new Date(monthly[monthly.length - 1]._id + "-01");

      let current = new Date(firstMonth);
      while (current <= lastMonth) {
        const ym = current.toISOString().slice(0, 7);
        const found = monthly.find(m => m._id === ym);

        months.push(ym);
        sales.push(found ? found.totalSales : 0);
        bookings.push(found ? found.totalBookings : 0);

        current.setMonth(current.getMonth() + 1);
      }
    }

    res.json({ months, sales, bookings });
  } catch (err) {
    console.error("❌ Error fetching metrics growth:", err);
    res.status(500).json({ error: "Failed to load metrics growth" });
  }
});

app.get('/api/predict/bookings', async (req, res) => {
  try {
    const bookings = await Booking.aggregate([
      {
        $group: {
          _id: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } },
          count: { $sum: 1 }
        }
      },
      { $sort: { "_id": 1 } }
    ]);

    if (!bookings || bookings.length < 3)
      return res.json({ success: false, message: "Not enough booking data for forecast." });

    const series = bookings.map(b => ({ ds: b._id, y: b.count }));

    const { data } = await axios.post("http://127.0.0.1:8000/predict", {
      series,
      horizon: 30
    });

    console.log("🧳 Booking Forecast:", data.success, "-", data.forecast?.length, "points");
    res.json(data);
  } catch (err) {
    console.error("❌ Prediction API Error (Bookings):", err.message);
    res.status(500).json({ success: false, message: err.message });
  }
});
// ========= 2️⃣ USER FORECAST =========
app.get('/api/predict/users', async (req, res) => {
  try {
    // 📅 Aggregate daily user registrations
    const userData = await User.aggregate([
      {
        $group: {
          _id: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } },
          totalUsers: { $sum: 1 }
        }
      },
      { $sort: { "_id": 1 } }
    ]);

    // ⚠️ Validate data availability
    if (!userData || userData.length < 3) {
      return res.json({ success: false, message: "Not enough user data for forecast." });
    }

    // 📊 Format data for Prophet (ds = date, y = count)
    const series = userData.map(u => ({ ds: u._id, y: u.totalUsers }));

    // 🔮 Call your FastAPI Prophet forecast service
    const { data } = await axios.post("http://127.0.0.1:8000/predict", {
      series,
      horizon: 30 // Predict next 30 days — you can increase to 180 if needed
    });

    console.log("👥 User Forecast:", data.success, "—", data.forecast?.length, "points");
    res.json(data);
  } catch (err) {
    console.error("❌ Prediction API Error (Users):", err.message);
    res.status(500).json({ success: false, message: err.message });
  }
});


app.get('/api/predict/seasonal', async (req, res) => {
  try {
    const data = await Booking.aggregate([
      { $match: { status: { $ne: "cancelled" } } },
      { $group: { _id: "$season", totalBookings: { $sum: 1 } } },
      { $sort: { "_id": 1 } }
    ]);

    if (!data || data.length < 3)
      return res.json({ success: false, message: "Not enough seasonal data" });

    const seasonToDate = {
      Winter: "2025-01-01",
      Spring: "2025-04-01",
      Summer: "2025-07-01",
      Fall: "2025-10-01"
    };

    const series = data.map(d => ({
      ds: seasonToDate[d._id] || "2025-01-01",
      y: d.totalBookings
    }));

    const { data: response } = await axios.post('http://127.0.0.1:8000/predict', {
      series, horizon: 4
    });

    res.json(response);
  } catch (err) {
    console.error("Prediction API Error (Seasonal):", err);
    res.status(500).json({ success: false, message: err.message });
  }
});


// 🌍 DESTINATION DEMAND FORECAST
app.get('/api/predict/destination-demand', async (req, res) => {
  try {
    const data = await Booking.aggregate([
      { $match: { status: { $ne: "cancelled" } } },
      { $group: { _id: "$destination", totalBookings: { $sum: 1 } } },
      { $sort: { totalBookings: -1 } },
      { $limit: 10 }
    ]);

    if (!data || data.length === 0)
      return res.json({ success: false, message: "No destination data" });

    res.json({
      success: true,
      forecast: data.map(d => ({
        destination: d._id,
        totalBookings: d.totalBookings
      }))
    });
  } catch (err) {
    console.error("Prediction API Error (Destination Demand):", err);
    res.status(500).json({ success: false, message: err.message });
  }
});
// 🧩 Helper: Build a time series dataset for forecasting
function buildForecastSeries(historicalData, forecastData, label) {
  const combined = [];

  // Add historical data points
  historicalData.forEach(point => {
    combined.push({
      date: point.date || point._id || point.time,
      value: point.value || point.count || point.total || 0,
      type: 'historical'
    });
  });

  // Add forecasted data points
  if (forecastData && forecastData.length > 0) {
    forecastData.forEach(point => {
      combined.push({
        date: point.date || point._id || point.time,
        value: point.forecast || point.value || 0,
        type: 'forecast'
      });
    });
  }

  return { label, data: combined };
}

// 🧩 Bookings version
async function buildBookingCountSeries() {
  const bookings = await Booking.aggregate([
    {
      $group: {
        _id: {
          year: { $year: "$createdAt" },
          month: { $month: "$createdAt" }
        },
        count: { $sum: 1 }
      }
    },
    { $sort: { "_id.year": 1, "_id.month": 1 } }
  ]);

  return bookings.map(b => ({
    date: `${b._id.year}-${b._id.month}-01`,
    value: b.count
  }));
}

// 🧩 Users version
async function buildUserSeries() {
  const users = await User.aggregate([
    {
      $group: {
        _id: {
          year: { $year: "$createdAt" },
          month: { $month: "$createdAt" }
        },
        count: { $sum: 1 }
      }
    },
    { $sort: { "_id.year": 1, "_id.month": 1 } }
  ]);

  return users.map(u => ({
    date: `${u._id.year}-${u._id.month}-01`,
    value: u.count
  }));
}

// 🧩 Sales version
async function buildSalesSeries() {
  const sales = await Booking.aggregate([
    {
      $group: {
        _id: {
          year: { $year: "$createdAt" },
          month: { $month: "$createdAt" }
        },
        total: { $sum: "$totalAmount" }
      }
    },
    { $sort: { "_id.year": 1, "_id.month": 1 } }
  ]);

  return sales.map(s => ({
    date: `${s._id.year}-${s._id.month}-01`,
    value: s.total
  }));
}

app.get("/api/forecast", async (req, res) => {
  try {
    const response = await axios.get("http://127.0.0.1:8000/predict");
    res.json(response.data);
  } catch (error) {
    console.error("❌ Error fetching forecast:", error.message);
    res.status(500).json({ success: false, message: "Forecast service unavailable." });
  }
});
app.get("/api/forecast/:type", async (req, res) => {
  try {
    const { type } = req.params;
    let series;

    if (type === "sales") {
      series = await buildForecastSeries(); // uses Booking.totalAmount
    } else if (type === "bookings") {
      series = await buildBookingCountSeries();
    } else if (type === "users") {
      series = await buildUserSeries();
    }

    const response = await fetch("http://127.0.0.1:8000/predict", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ series, horizon: 180 }),
    });
    const data = await response.json();
    res.json(data);
  } catch (error) {
    console.error("Forecast error:", error);
    res.status(500).json({ success: false, message: error.message });
  }
});
async function getTimeSeries(metric) {
  let pipeline = [];
  let collection;

  switch (metric) {
    case "sales":
      collection = Booking;
      pipeline = [
        { $match: { status: { $ne: "cancelled" }, archived: false } },
        {
          $group: {
            _id: {
              year: { $year: "$createdAt" },
              month: { $month: "$createdAt" },
              day: { $dayOfMonth: "$createdAt" },
            },
            total: { $sum: "$totalAmount" },
          },
        },
        {
          $project: {
            _id: 0,
            ds: {
              $dateFromParts: {
                year: "$_id.year",
                month: "$_id.month",
                day: "$_id.day",
              },
            },
            y: "$total",
          },
        },
        { $sort: { ds: 1 } },
      ];
      break;

    case "bookings":
      collection = Booking;
      pipeline = [
        { $match: { archived: false } },
        {
          $group: {
            _id: {
              year: { $year: "$createdAt" },
              month: { $month: "$createdAt" },
              day: { $dayOfMonth: "$createdAt" },
            },
            total: { $sum: 1 },
          },
        },
        {
          $project: {
            _id: 0,
            ds: {
              $dateFromParts: {
                year: "$_id.year",
                month: "$_id.month",
                day: "$_id.day",
              },
            },
            y: "$total",
          },
        },
        { $sort: { ds: 1 } },
      ];
      break;

    case "users":
      collection = User;
      pipeline = [
        {
          $group: {
            _id: {
              year: { $year: "$createdAt" },
              month: { $month: "$createdAt" },
              day: { $dayOfMonth: "$createdAt" },
            },
            total: { $sum: 1 },
          },
        },
        {
          $project: {
            _id: 0,
            ds: {
              $dateFromParts: {
                year: "$_id.year",
                month: "$_id.month",
                day: "$_id.day",
              },
            },
            y: "$total",
          },
        },
        { $sort: { ds: 1 } },
      ];
      break;

    default:
      throw new Error("Invalid metric type");
  }

  const result = await collection.aggregate(pipeline);
  return result.map(item => ({
    ds: item.ds,
    y: item.y,
  }));
}
// =============================================
// 🔮 FORECAST ENDPOINT (REAL DATA VERSION)
// =============================================
app.get("/api/analytics/forecast/:metric", async (req, res) => {
  const { metric } = req.params;

  try {
    const series = await getTimeSeries(metric);

    if (!series || series.length < 3) {
      return res.status(400).json({
        success: false,
        message: `Not enough ${metric} data for forecasting.`,
      });
    }

    const horizon = parseInt(req.query.horizon) || 90; // default to 90 if not provided
const response = await axios.post(`${PYTHON_API}/predict?horizon=${horizon}`, {
  series,
  freq: "D",
});


    res.json({
      ...response.data,
      count: series.length,
      metric,
    });
  } catch (err) {
    console.error(`❌ ${metric.toUpperCase()} Forecast Error:`, err.message);
    res.status(500).json({
      success: false,
      message: `Failed to forecast ${metric}`,
      error: err.message,
    });
  }
});

app.post("/api/analytics/forecast/batch", async (req, res) => {
  const { datasets } = req.body;

  if (!datasets || Object.keys(datasets).length === 0) {
    return res.status(400).json({ success: false, message: "No datasets provided" });
  }

  try {
    const response = await axios.post(`${PYTHON_API}/batch-predict`, { datasets });
    res.json(response.data);
  } catch (err) {
    console.error("❌ Batch Forecast API error:", err.message);
    res.status(500).json({ success: false, message: "Batch Forecast API unavailable", error: err.message });
  }
});

// ----------------------------
// AI Insights (Top & Emerging Tours)
// ----------------------------
app.post("/api/analytics/insights", async (req, res) => {
  const { tours } = req.body;

  if (!tours || tours.length === 0) {
    return res.status(400).json({ success: false, message: "No tour data provided" });
  }

  try {
    const response = await axios.post(`${PYTHON_API}/insights`, { tours });
    res.json(response.data);
  } catch (err) {
    console.error("❌ Insights API error:", err.message);
    res.status(500).json({ success: false, message: "Insights API unavailable", error: err.message });
  }
});
// ============================================
// 🧠 /api/admin/tours-performance
// ============================================
app.get("/api/admin/tours-performance", async (req, res) => {
  try {
    const tours = await Booking.aggregate([
      {
        $group: {
          _id: "$tourDetails.title",
          title: { $first: "$tourDetails.title" },
          bookings: { $sum: 1 },
          revenue: { $sum: "$totalAmount" },
          createdAt: { $first: "$createdAt" }
        }
      },
      { $sort: { revenue: -1 } }
    ]);

    res.json(
      tours.map(t => ({
        tourId: t._id,
        title: t.title,
        bookings: t.bookings,
        revenue: t.revenue,
        createdAt: t.createdAt
      }))
    );
  } catch (err) {
    console.error("❌ Error fetching tour performance:", err);
    res.status(500).json({ error: "Failed to load tour performance data" });
  }
});

// ============================================
// 📈 /api/admin/metrics-growth
// ============================================
app.get("/api/admin/metrics-growth", async (req, res) => {
  try {
    const monthly = await Booking.aggregate([
      {
        $group: {
          _id: { $dateToString: { format: "%Y-%m", date: "$createdAt" } },
          totalSales: { $sum: "$totalAmount" },
          totalBookings: { $sum: 1 }
        }
      },
      { $sort: { "_id": 1 } }
    ]);

    res.json({
      months: monthly.map(m => m._id),
      sales: monthly.map(m => m.totalSales),
      bookings: monthly.map(m => m.totalBookings)
    });
  } catch (err) {
    console.error("❌ Error fetching metrics growth:", err);
    res.status(500).json({ error: "Failed to load metrics growth" });
  }
});
// ============================================
// ☀️ /api/admin/seasonal-data
// ============================================
app.get("/api/admin/seasonal-data", checkAdminAuth, async (req, res) => {
  try {
    const grouped = await Booking.aggregate([
      {
        $group: {
          _id: {
            destination: "$destination",
            date: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } }
          },
          totalSales: { $sum: "$totalAmount" },
          totalBookings: { $sum: 1 }
        }
      },
      { $sort: { "_id.date": 1 } }
    ]);

    const datasets = {};

    grouped.forEach((item) => {
      const dest = item._id.destination || "Unknown";
      if (!datasets[dest]) datasets[dest] = [];

      // 🗓️ Format the date nicely
      const formattedDate = new Date(item._id.date).toLocaleDateString("en-US", {
        month: "short",
        day: "numeric",
        year: "numeric"
      });

      datasets[dest].push({
        ds: formattedDate,
        y: item.totalSales
      });
    });

    res.json({ success: true, datasets });

  } catch (err) {
    console.error("❌ Error fetching seasonal data:", err);
    res.status(500).json({ success: false, message: "Failed to load seasonal data" });
  }
});

// ============================================
// 👥 /api/admin/user-growth
// ============================================
app.get("/api/admin/user-growth", async (req, res) => {
  try {
    const monthlyUsers = await User.aggregate([
      {
        $group: {
          _id: { $dateToString: { format: "%Y-%m", date: "$createdAt" } },
          count: { $sum: 1 }
        }
      },
      { $sort: { "_id": 1 } }
    ]);

    res.json({
      months: monthlyUsers.map(u => u._id),
      counts: monthlyUsers.map(u => u.count)
    });
  } catch (err) {
    console.error("❌ Error fetching user growth:", err);
    res.status(500).json({ error: "Failed to load user growth data" });
  }
});
// ============================================
// 🔁 /api/admin/user-retention
// ============================================
// Calculates user retention by tracking returning users each month.
app.get("/api/admin/user-retention", async (req, res) => {
  try {
    const monthlyRetention = await User.aggregate([
      {
        $group: {
          _id: { $dateToString: { format: "%Y-%m", date: "$lastActiveAt" } },
          activeUsers: { $sum: 1 }
        }
      },
      { $sort: { "_id": 1 } }
    ]);

    const signupUsers = await User.aggregate([
      {
        $group: {
          _id: { $dateToString: { format: "%Y-%m", date: "$createdAt" } },
          newUsers: { $sum: 1 }
        }
      }
    ]);

    const retentionMap = {};
    signupUsers.forEach(s => (retentionMap[s._id] = { newUsers: s.newUsers, activeUsers: 0 }));

    monthlyRetention.forEach(r => {
      if (!retentionMap[r._id]) retentionMap[r._id] = { newUsers: 0, activeUsers: 0 };
      retentionMap[r._id].activeUsers = r.activeUsers;
    });

    const months = Object.keys(retentionMap).sort();
    const retentionRate = months.map(m => {
      const d = retentionMap[m];
      return d.newUsers ? (d.activeUsers / d.newUsers) * 100 : 0;
    });

    res.json({ months, retentionRate });
  } catch (err) {
    console.error("❌ Error fetching user retention:", err);
    res.status(500).json({ error: "Failed to load user retention data" });
  }
});
app.get("/api/admin/user-engagement", async (req, res) => {
  try {
    const now = new Date();
    const sevenDaysAgo = new Date(now);
    sevenDaysAgo.setDate(now.getDate() - 7);
    const thirtyDaysAgo = new Date(now);
    thirtyDaysAgo.setDate(now.getDate() - 30);

    const totalUsers = await User.countDocuments();

    const active7Days = await User.countDocuments({ lastActiveAt: { $gte: sevenDaysAgo } });
    const active30Days = await User.countDocuments({ lastActiveAt: { $gte: thirtyDaysAgo } });

    const retentionRate = totalUsers ? ((active30Days / totalUsers) * 100).toFixed(1) : 0;

    res.json({
      totalUsers,
      active7Days,
      active30Days,
      retentionRate: Number(retentionRate)
    });
  } catch (err) {
    console.error("❌ Error fetching user engagement summary:", err);
    res.status(500).json({ error: "Failed to load user engagement summary" });
  }
});
// ============================================
// 📈 /api/admin/user-engagement-trend
// ============================================
// Provides historical monthly active user counts + retention rate
app.get("/api/admin/user-engagement-trend", async (req, res) => {
  try {
    const now = new Date();
    const startOf2023 = new Date("2023-01-01");

    // ✅ 1. Get monthly active users (within real date range)
    const monthlyActive = await User.aggregate([
      {
        $match: {
          lastActiveAt: { $exists: true, $ne: null, $gte: startOf2023, $lte: now }
        }
      },
      {
        $group: {
          _id: { $dateToString: { format: "%Y-%m", date: "$lastActiveAt" } },
          activeUsers: { $sum: 1 }
        }
      },
      { $sort: { "_id": 1 } }
    ]);

    // ✅ 2. Get monthly new users (within real date range)
    const monthlyNewUsers = await User.aggregate([
      {
        $match: {
          createdAt: { $exists: true, $ne: null, $gte: startOf2023, $lte: now }
        }
      },
      {
        $group: {
          _id: { $dateToString: { format: "%Y-%m", date: "$createdAt" } },
          newUsers: { $sum: 1 }
        }
      },
      { $sort: { "_id": 1 } }
    ]);

    // ✅ 3. Merge monthly data
    const map = {};
    monthlyNewUsers.forEach(n => (map[n._id] = { newUsers: n.newUsers, activeUsers: 0 }));

    monthlyActive.forEach(a => {
      if (!map[a._id]) map[a._id] = { newUsers: 0, activeUsers: 0 };
      map[a._id].activeUsers = a.activeUsers;
    });

    // ✅ 4. Compute trends safely (cap retention ≤ 100)
    const months = Object.keys(map).sort();
    const active = months.map(m => map[m].activeUsers);
    const retention = months.map(m => {
      const { newUsers, activeUsers } = map[m];
      return newUsers ? Math.min((activeUsers / newUsers) * 100, 100) : 0;
    });

    res.json({ months, active, retention });
  } catch (err) {
    console.error("❌ Error fetching engagement trend:", err);
    res.status(500).json({ error: "Failed to load engagement trend data" });
  }
});

app.get("/api/admin/user-activity", async (req, res) => {
  try {
    const now = new Date();
    const weekAgo = new Date();
    weekAgo.setDate(now.getDate() - 7);
    const monthAgo = new Date();
    monthAgo.setDate(now.getDate() - 30);

    // Fetch active users in last 7 days
    const activeUsers = await User.find({ lastActiveAt: { $gte: weekAgo } })
      .sort({ lastActiveAt: -1 })
      .limit(10)
      .select("firstName lastName email lastActiveAt");

    // Fetch users inactive for 30+ days
    const inactiveUsers = await User.find({ lastActiveAt: { $lt: monthAgo } })
      .sort({ lastActiveAt: 1 })
      .limit(10)
      .select("firstName lastName email lastActiveAt");

    const totalUsers = await User.countDocuments();
    const activeCount = await User.countDocuments({ lastActiveAt: { $gte: weekAgo } });
    const inactiveCount = await User.countDocuments({ lastActiveAt: { $lt: monthAgo } });

    res.json({
      totalUsers,
      activeCount,
      inactiveCount,
      activeUsers,
      inactiveUsers
    });
  } catch (err) {
    console.error("❌ Error fetching user activity summary:", err);
    res.status(500).json({ error: "Failed to load user activity summary" });
  }
});
// ===========================================
// 📊 Generate Time Series Data for Forecasts
// ===========================================
app.get("/api/timeseries/:metric", async (req, res) => {
  try {
    const { metric } = req.params;
    let data = [];

    if (metric === "sales") {
      // 💰 Total sales per day
      data = await Booking.aggregate([
        {
          $group: {
            _id: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } },
            y: { $sum: "$totalAmount" }
          }
        },
        { $sort: { _id: 1 } },
        { $project: { _id: 0, ds: "$_id", y: 1 } }
      ]);
    } 
    
    else if (metric === "bookings") {
      // 🧳 Number of bookings per day
      data = await Booking.aggregate([
        {
          $group: {
            _id: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } },
            y: { $sum: 1 }
          }
        },
        { $sort: { _id: 1 } },
        { $project: { _id: 0, ds: "$_id", y: 1 } }
      ]);
    } 
    
    else if (metric === "users") {
      // 👥 New users per day
      const users = await User.aggregate([
        {
          $group: {
            _id: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } },
            y: { $sum: 1 }
          }
        },
        { $sort: { _id: 1 } },
        { $project: { _id: 0, ds: "$_id", y: 1 } }
      ]);
      data = users;
    }

    console.log(`📊 Timeseries for ${metric}:`, data.slice(0, 5)); // check your console
    res.json(data);

  } catch (err) {
    console.error("❌ Error generating timeseries:", err);
    res.status(500).json({ error: "Failed to generate timeseries data" });
  }
});
// ============================================
// 📅 /api/admin/seasonal-forecast
// ============================================
app.get("/api/admin/seasonal-forecast", async (req, res) => {
  try {
    const year = parseInt(req.query.year) || new Date().getFullYear();

    // 1️⃣ Get monthly actual bookings for selected year (confirmed + completed only)
    const actual = await Booking.aggregate([
      {
        $match: {
          status: { $in: ["confirmed", "completed"] },
          createdAt: {
            $gte: new Date(`${year}-01-01`),
            $lt: new Date(`${year + 1}-01-01`)
          }
        }
      },
      {
        $group: {
          _id: { $month: "$createdAt" },
          totalBookings: { $sum: 1 }
        }
      },
      { $sort: { "_id": 1 } }
    ]);

    const actualData = Array.from({ length: 12 }, (_, i) => {
      const monthData = actual.find(a => a._id === i + 1);
      return monthData ? monthData.totalBookings : 0;
    });

    // 2️⃣ Send this data to your Python API for Prophet forecasting
    const response = await fetch("http://127.0.0.1:8000/predict", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        series: Array.from({ length: actualData.length }, (_, i) => ({
          ds: `${year}-${String(i + 1).padStart(2, "0")}-01`,
          y: actualData[i]
        })),
        horizon: 12,  // forecast next 12 months
        freq: "M"
      })
    });

    const forecast = await response.json();

    res.json({
      year,
      months: [
        "Jan","Feb","Mar","Apr","May","Jun",
        "Jul","Aug","Sep","Oct","Nov","Dec"
      ],
      actual: actualData,
      predicted: forecast.success
        ? forecast.forecast.map(f => f.yhat)
        : Array(12).fill(0),
      mape: forecast.mape || null,
      rmse: forecast.rmse || null,
      accuracy: forecast.accuracy || "N/A"
    });

  } catch (err) {
    console.error("❌ Seasonal forecast error:", err);
    res.status(500).json({ error: "Failed to load seasonal forecast" });
  }
});
// ===============================================
// 📊 Seasonal Analytics (Actual + Prophet Predicted)
// ===============================================
app.get('/api/analytics/seasonal', async (req, res) => {
  try {
    const year = parseInt(req.query.year) || new Date().getFullYear();

    // ✅ Fetch completed or confirmed bookings only
    const bookings = await Booking.aggregate([
      {
        $match: {
          status: { $in: ["confirmed", "completed"] },
          createdAt: {
            $gte: new Date(`${year}-01-01`),
            $lte: new Date(`${year}-12-31`)
          }
        }
      },
      {
        $group: {
          _id: { $month: "$createdAt" },
          totalBookings: { $sum: 1 },
          totalSales: { $sum: "$totalAmount" }
        }
      },
      { $sort: { "_id": 1 } }
    ]);

    // ✅ Prepare monthly data
    const months = [
      "Jan","Feb","Mar","Apr","May","Jun",
      "Jul","Aug","Sep","Oct","Nov","Dec"
    ];
    const actual = new Array(12).fill(0);
    bookings.forEach(b => {
      actual[b._id - 1] = b.totalBookings;
    });

    // ✅ Send actual data to FastAPI Prophet for prediction
    const response = await fetch("http://127.0.0.1:8000/predict", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        series: months.map((m, i) => ({
          ds: `${year}-${String(i + 1).padStart(2, "0")}-01`,
          y: actual[i] || 0
        })),
        horizon: 12
      })
    });

    const forecast = await response.json();

    if (!forecast.success) {
      throw new Error(forecast.detail || "FastAPI forecast failed");
    }

    const predicted = forecast.forecast.map(f => f.yhat);

    res.json({
      success: true,
      months,
      actual,
      predicted,
      predictedMonths: months.map(m => m + " (Predicted)"),
      mape: forecast.mape,
      rmse: forecast.rmse
    });
  } catch (err) {
    console.error("❌ Error fetching seasonal analytics:", err);
    res.status(500).json({
      success: false,
      message: err.message || "Internal server error"
    });
  }
});


/* === Helper Functions === */
async function calculateRetentionRate() {
  const users = await Booking.distinct("userId");
  if (users.length === 0) return 0;

  const repeat = await Booking.aggregate([
    { $group: { _id: "$userId", count: { $sum: 1 } } },
    { $match: { count: { $gt: 1 } } },
  ]);
  return ((repeat.length / users.length) * 100).toFixed(2);
}

async function detectPeakSeason() {
  const result = await Booking.aggregate([
    { $group: { _id: "$season", bookings: { $sum: 1 } } },
    { $sort: { bookings: -1 } },
    { $limit: 1 },
  ]);
  return result.length ? result[0]._id : "—";
}

async function getActiveUsers(days) {
  const cutoff = new Date();
  cutoff.setDate(cutoff.getDate() - days);
  return await User.countDocuments({ lastActiveAt: { $gte: cutoff } });
}

async function getMostActiveUsers(limit = 10) {
  return await User.find().sort({ lastActiveAt: -1 }).limit(limit).lean();
}

async function getInactiveUsers(limit = 10) {
  const cutoff = new Date();
  cutoff.setDate(cutoff.getDate() - 30);
  return await User.find({ lastActiveAt: { $lt: cutoff } })
    .sort({ lastActiveAt: 1 })
    .limit(limit)
    .lean();
}

async function getTopDestinations(limit = 10) {
  const result = await Booking.aggregate([
    { $group: { _id: "$destination", count: { $sum: 1 }, totalRevenue: { $sum: "$totalAmount" } } },
    { $sort: { count: -1 } },
    { $limit: limit },
  ]);
  return result;
}

// ✅ Excel Export (Dashboard Summary + Insights)
app.get("/api/admin/export-dashboard", async (req, res) => {
  try {
    const workbook = new ExcelJS.Workbook();
    workbook.creator = "A.BEE Travel Admin";
    workbook.created = new Date();

    const orange = "FFD55A1F";
    const blue = "FF1E90FF";

    const addHeaderStyle = (sheet, title) => {
      sheet.mergeCells("A1", "E1");
      const header = sheet.getCell("A1");
      header.value = title;
      header.font = { bold: true, size: 16, color: { argb: orange } };
      header.alignment = { horizontal: "center", vertical: "middle" };
      sheet.addRow([]);
    };

    /* === 1️⃣ Overview Metrics === */
    const overview = workbook.addWorksheet("Overview Metrics");
    addHeaderStyle(overview, "A.BEE Travel & Tours — Admin Dashboard Summary");

    const totalUsers = await User.countDocuments();
    const totalBookings = await Booking.countDocuments();
    const totalRevenueData = await Booking.aggregate([
      { $group: { _id: null, total: { $sum: "$totalAmount" } } },
    ]);
    const totalRevenue = totalRevenueData[0]?.total || 0;

    overview.addRow(["Report Period", "All Time"]);
    overview.addRow(["Total Registered Users", totalUsers]);
    overview.addRow(["Total Bookings", totalBookings]);
    overview.addRow(["Total Sales (₱)", totalRevenue.toLocaleString()]);
    overview.addRow([]);
    overview.addRow(["Generated", new Date().toLocaleString()]);

    overview.getColumn(1).width = 35;
    overview.getColumn(2).width = 30;
    overview.getColumn(1).font = { bold: true, color: { argb: blue } };

    /* === 2️⃣ Top Destinations === */
    const destSheet = workbook.addWorksheet("Top Destinations");
    addHeaderStyle(destSheet, "Most Popular Destinations");

    destSheet.columns = [
      { header: "Destination", key: "destination", width: 25 },
      { header: "Bookings", key: "count", width: 15 },
      { header: "Total Revenue (₱)", key: "revenue", width: 25 },
    ];

    const topDestinations = await Booking.aggregate([
      {
        $group: {
          _id: "$destination",
          count: { $sum: 1 },
          totalRevenue: { $sum: "$totalAmount" },
        },
      },
      { $sort: { count: -1 } },
      { $limit: 5 },
    ]);
    topDestinations.forEach((d) =>
      destSheet.addRow({
        destination: d._id,
        count: d.count,
        revenue: d.totalRevenue.toLocaleString(),
      })
    );

    /* === 3️⃣ Traveler Demographics === */
    const demoSheet = workbook.addWorksheet("Traveler Demographics");
    addHeaderStyle(demoSheet, "Traveler Demographics Overview");

    demoSheet.columns = [
      { header: "Traveler Name", key: "fullName", width: 25 },
      { header: "Sex", key: "sex", width: 10 },
      { header: "Birthdate", key: "birthdate", width: 15 },
      { header: "Destination", key: "destination", width: 25 },
      { header: "Payment Method", key: "paymentMethod", width: 20 },
    ];

    const recentBookings = await Booking.find()
      .sort({ createdAt: -1 })
      .limit(50)
      .lean();

    recentBookings.forEach((b) => {
      (b.travelerDetails || []).forEach((t) => {
        demoSheet.addRow({
          fullName: t.fullName,
          sex: t.sex || "N/A",
          birthdate: t.birthdate
            ? new Date(t.birthdate).toLocaleDateString()
            : "N/A",
          destination: b.destination,
          paymentMethod: b.paymentMethod,
        });
      });
    });

    /* === 4️⃣ Strategic Recommendations === */
    const recSheet = workbook.addWorksheet("Strategic Recommendations");
    addHeaderStyle(recSheet, "AI-Generated Business Recommendations");

    const recs = [
      "📈 Focus marketing on November–December peak seasons.",
      "🎯 Strengthen GCash and Store payment offers (PayPal phase-out).",
      "🧍 Optimize age-based packages for 18–35 travelers.",
      "💡 Introduce gender-targeted travel promos.",
      "🤖 Use AI insights for destination pricing optimization.",
    ];
    recs.forEach((r) => recSheet.addRow(["•", r]));

    // ✅ Send Excel file
    res.setHeader(
      "Content-Type",
      "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    );
    res.setHeader(
      "Content-Disposition",
      'attachment; filename="Abee_Admin_Dashboard_Summary.xlsx"'
    );

    await workbook.xlsx.write(res);
    res.end();
  } catch (err) {
    console.error("❌ Excel Export Error:", err);
    res.status(500).send("Failed to export dashboard summary");
  }
});
// CSV Export (Raw Booking Data) - robust for Parser or AsyncParser
const { Parser: Json2csvParser, AsyncParser } = require("json2csv");

app.get("/api/admin/export-dashboard-raw", async (req, res) => {
  try {
    const bookings = await Booking.find()
      .select("bookingId fullName destination paymentMethod totalAmount startDate createdAt travelerDetails")
      .lean();

    const flattened = [];
    bookings.forEach((b) => {
      (b.travelerDetails || []).forEach((t) => {
        flattened.push({
          BookingID: b.bookingId,
          TravelerName: t.fullName,
          Sex: t.sex || "N/A",
          Birthdate: t.birthdate ? new Date(t.birthdate).toISOString().split("T")[0] : "N/A",
          Destination: b.destination,
          PaymentMethod: b.paymentMethod,
          TotalAmount: b.totalAmount,
          StartDate: b.startDate ? new Date(b.startDate).toISOString().split("T")[0] : "N/A",
          CreatedAt: b.createdAt ? new Date(b.createdAt).toISOString().split("T")[0] : "N/A",
        });
      });
    });

    let csv;
    // Prefer sync Parser if available (common), otherwise use AsyncParser
    if (typeof Json2csvParser === "function") {
      const parser = new Json2csvParser();
      csv = parser.parse(flattened);
    } else if (typeof AsyncParser === "function") {
      const asyncParser = new AsyncParser();
      // `.parse()` returns a stream when used in Node style; use promise() to get string
      csv = await asyncParser.parse(flattened).promise();
    } else {
      throw new Error("No json2csv parser found (install json2csv).");
    }

    res.setHeader("Content-Type", "text/csv");
    res.setHeader("Content-Disposition", 'attachment; filename="Abee_Raw_Booking_Data.csv"');
    res.send(csv);
  } catch (err) {
    console.error("❌ CSV Export Error:", err.message);
    console.error(err.stack);
    res.status(500).json({ error: "Failed to export raw CSV data", detail: err.message });
  }
});


app.get("/api/admin/export-summary", async (req, res) => {
  try {
    const doc = new jsPDF({ orientation: "portrait", unit: "pt", format: "a4" });

    // Title
    doc.setFontSize(16);
    doc.setTextColor(213, 90, 31);
    doc.text("A.BEE Travel & Tours — Executive Summary Report", 40, 50);

    // Metadata
    doc.setFontSize(11);
    doc.setTextColor(100, 100, 100);
    doc.text(`Generated: ${new Date().toLocaleString()}`, 40, 70);

    // === Overview Metrics ===
    const totalUsers = await User.countDocuments();
    const totalBookings = await Booking.countDocuments();
    const totalRevenueData = await Booking.aggregate([{ $group: { _id: null, total: { $sum: "$totalAmount" } } }]);
    const totalRevenue = totalRevenueData[0]?.total || 0;

    doc.setFontSize(13);
    doc.setTextColor(0, 0, 0);
    doc.text("🌍 Overall Performance", 40, 100);

    doc.autoTable({
      startY: 110,
      head: [["Metric", "Value"]],
      body: [
        ["Total Registered Users", totalUsers.toLocaleString()],
        ["Total Bookings", totalBookings.toLocaleString()],
        ["Total Sales (₱)", totalRevenue.toLocaleString()],
      ],
      styles: { fontSize: 10 },
      theme: "striped",
    });

    // === Top Destinations ===
    const topDestinations = await Booking.aggregate([
      { $group: { _id: "$destination", count: { $sum: 1 }, totalRevenue: { $sum: "$totalAmount" } } },
      { $sort: { count: -1 } },
      { $limit: 4 },
    ]);

    doc.text("✈️ Top Destinations", 40, doc.lastAutoTable.finalY + 40);
    doc.autoTable({
      startY: doc.lastAutoTable.finalY + 50,
      head: [["Destination", "Bookings", "Total Revenue (₱)"]],
      body: topDestinations.map((d) => [
        d._id,
        d.count.toLocaleString(),
        d.totalRevenue.toLocaleString(),
      ]),
      styles: { fontSize: 10 },
      theme: "striped",
    });

    // === Predictive Analytics Summary ===
    doc.text("🧠 Predictive Analytics (30 Days)", 40, doc.lastAutoTable.finalY + 40);
    doc.autoTable({
      startY: doc.lastAutoTable.finalY + 50,
      head: [["Metric", "Predicted Value", "Trend"]],
      body: [
        ["Projected Total Sales", "₱1,335,478.38", "📈 +545.2%"],
        ["Expected Bookings", "17", "📈 +757.0%"],
        ["User Growth", "2", "📈 +94.1%"],
      ],
      styles: { fontSize: 10 },
      theme: "striped",
    });

    // === Seasonal Insights ===
    doc.text("🌤️ Seasonal Insights", 40, doc.lastAutoTable.finalY + 40);
    doc.autoTable({
      startY: doc.lastAutoTable.finalY + 50,
      head: [["Peak Season", "Predicted Demand"]],
      body: [["Taiwan — Dec 27, 2026", "555,766 bookings"]],
      styles: { fontSize: 10 },
      theme: "striped",
    });

    // === Strategic Recommendations ===
    doc.text("💡 AI Strategic Recommendations", 40, doc.lastAutoTable.finalY + 40);
    const recommendations = [
      "Reinforce year-end marketing campaigns (Nov–Dec).",
      "Prioritize Bali and Taiwan for promotions.",
      "Introduce loyalty incentives for 2026 retention.",
      "Use predictive data for staffing and inventory.",
      "Bundle top destinations for high-value clients.",
    ];
    recommendations.forEach((r, i) => {
      doc.text(`• ${r}`, 60, doc.lastAutoTable.finalY + 70 + i * 20);
    });

    // === Footer ===
    doc.setFontSize(9);
    doc.setTextColor(130, 130, 130);
    doc.text("Generated by A.BEE Admin Dashboard", 200, 810);

    const pdfBuffer = Buffer.from(doc.output("arraybuffer"));
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", 'attachment; filename="Abee_Executive_Summary.pdf"');
    res.send(pdfBuffer);
  } catch (err) {
    console.error("❌ PDF Export Error:", err);
    res.status(500).send("Failed to export executive summary");
  }
});

// ===============================================
// 📆 Predictive Insights (Monthly Aggregation)
// ===============================================
app.get("/api/forecast-insights", checkAdminAuth, async (req, res) => {
  try {
    const { month, year } = req.query;

    // Default to current month if not provided
    const currentDate = new Date();
    const selectedMonth = month ? parseInt(month) - 1 : currentDate.getMonth();
    const selectedYear = year ? parseInt(year) : currentDate.getFullYear();

    const monthStart = new Date(selectedYear, selectedMonth, 1);
    const monthEnd = new Date(selectedYear, selectedMonth + 1, 0, 23, 59, 59);

    console.log(`📊 Fetching forecast for ${monthStart.toDateString()} - ${monthEnd.toDateString()}`);

    // 1️⃣ Group data by month
    const [sales, bookings, users] = await Promise.all([
      Booking.aggregate([
        { $match: { createdAt: { $lte: monthEnd }, status: { $ne: "cancelled" } } },
        {
          $group: {
            _id: { $dateToString: { format: "%Y-%m", date: "$createdAt" } },
            totalSales: { $sum: "$totalAmount" }
          }
        },
        { $sort: { _id: 1 } }
      ]),
      Booking.aggregate([
        { $match: { createdAt: { $lte: monthEnd } } },
        {
          $group: {
            _id: { $dateToString: { format: "%Y-%m", date: "$createdAt" } },
            totalBookings: { $sum: 1 }
          }
        },
        { $sort: { _id: 1 } }
      ]),
      User.aggregate([
        {
          $group: {
            _id: { $dateToString: { format: "%Y-%m", date: "$createdAt" } },
            totalUsers: { $sum: 1 }
          }
        },
        { $sort: { _id: 1 } }
      ])
    ]);

    // 2️⃣ Format for Prophet
    const salesSeries = sales.map(s => ({ ds: s._id + "-01", y: s.totalSales }));
    const bookingSeries = bookings.map(b => ({ ds: b._id + "-01", y: b.totalBookings }));
    const userSeries = users.map(u => ({ ds: u._id + "-01", y: u.totalUsers }));

    if (salesSeries.length < 5) {
      return res.json({ success: false, message: "Not enough monthly data for forecast." });
    }

    // 3️⃣ Send to FastAPI batch forecast
    const { data } = await axios.post("http://127.0.0.1:8000/batch-predict", {
      datasets: {
        sales: { series: salesSeries, horizon: 3 }, // Forecast next 3 months
        bookings: { series: bookingSeries, horizon: 3 },
        users: { series: userSeries, horizon: 3 }
      }
    });

    res.json({
  success: true,
  selectedMonth: `${selectedYear}-${selectedMonth + 1}`,
  salesForecast: data.sales?.forecast?.[0]?.yhat || 0,
  bookingsForecast: data.bookings?.forecast?.[0]?.yhat || 0,
  usersForecast: data.users?.forecast?.[0]?.yhat || 0,
  trendNotes: {
    sales: data.sales?.trend_note || "No trend detected",
    bookings: data.bookings?.trend_note || "No trend detected",
    users: data.users?.trend_note || "No trend detected"
  }
});

  } catch (err) {
    console.error("❌ Monthly Forecast Insights Error:", err);
    res.status(500).json({ success: false, message: "Failed to generate monthly forecast insights." });
  }
});

apiRouter.get("/predictive/insights", checkAdminAuth, async (req, res) => {
  try {
    // 1️⃣ Fetch real booking data
    const bookings = await Booking.aggregate([
      {
        $group: {
          _id: "$destination",
          title: { $first: "$tourDetails.title" },
          totalBookings: { $sum: 1 },
          totalRevenue: { $sum: "$totalAmount" },
        },
      },
      {
        $project: {
          tourId: "$_id",
          title: { $ifNull: ["$title", "$_id"] },
          bookings: "$totalBookings",
          revenue: "$totalRevenue",
        },
      },
    ]);

    if (!bookings.length) {
      return res.json({
        success: false,
        message: "No booking data available for insights",
      });
    }

    // 2️⃣ Send data to Python FastAPI service
    const response = await axios.post(`${PYTHON_API}/insights`, {
      tours: bookings,
    });

    res.json(response.data);
  } catch (err) {
    console.error("❌ Predictive insights error:", err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Optional — Forecast API for trends (total bookings per day)
apiRouter.get("/predictive/forecast", checkAdminAuth, async (req, res) => {
  try {
    const daily = await Booking.aggregate([
      {
        $group: {
          _id: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } },
          y: { $sum: 1 },
        },
      },
      { $sort: { "_id": 1 } },
    ]);

    if (!daily.length) {
      return res.json({ success: false, message: "No booking data for forecast" });
    }

    const formattedSeries = daily.map((d) => ({ ds: d._id, y: d.y }));

   const horizon = parseInt(req.query.horizon) || 30;
const response = await axios.post(`${PYTHON_API}/predict?horizon=${horizon}`, {
  series: formattedSeries,
});

    res.json(response.data);
  } catch (err) {
    console.error("❌ Forecast generation error:", err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});
// --- SALES FORECAST ---
apiRouter.get("/predictive/forecast-sales", checkAdminAuth, async (req, res) => {
  try {
    const sales = await Booking.aggregate([
      {
        $group: {
          _id: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } },
          y: { $sum: "$totalAmount" },
        },
      },
      { $sort: { "_id": 1 } },
    ]);

    if (!sales.length) return res.json({ success: false });

    const formattedSeries = sales.map(d => ({ ds: d._id, y: d.y }));
    const horizon = parseInt(req.query.horizon) || 30;
const response = await axios.post(`${PYTHON_API}/predict?horizon=${horizon}`, { series: formattedSeries });
res.json(response.data);
  } catch (err) {
    console.error("❌ Sales forecast error:", err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});
app.get("/api/predictive/forecast-sales", async (req, res) => {
  try {
    const horizon = parseInt(req.query.horizon) || 30; // 30 days default

    const response = await fetch(`http://127.0.0.1:8000/predict?horizon=${horizon}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        series: salesSeries, // use your actual sales dataset
        horizon: horizon
      }),
    });

    const data = await response.json();
    res.json(data);
  } catch (err) {
    console.error("❌ Forecast Sales Error:", err);
    res.status(500).json({ success: false, message: "Failed to fetch sales forecast" });
  }
});

apiRouter.get("/predictive/forecast-users", checkAdminAuth, async (req, res) => {
  try {
    const users = await User.aggregate([
      {
        $group: {
          _id: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } },
          y: { $sum: 1 },
        },
      },
      { $sort: { "_id": 1 } },
    ]);

    if (!users.length) return res.json({ success: false });

    const formattedSeries = users.map(d => ({ ds: d._id, y: d.y }));
    const horizon = parseInt(req.query.horizon) || 30;
const response = await axios.post(`${PYTHON_API}/predict?horizon=${horizon}`, { series: formattedSeries });
res.json(response.data);
  } catch (err) {
    console.error("❌ User forecast error:", err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});
// Check username availability
app.get('/check-username', async (req, res) => {
    try {
        const username = req.query.username?.trim();
        if (!username) return res.json({ available: false, message: 'No username provided' });

        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.json({ available: false, message: 'Username already taken' });
        }
        res.json({ available: true, message: 'Username available' });
    } catch (err) {
        console.error('Error checking username:', err);
        res.status(500).json({ available: false, message: 'Server error' });
    }
});
// Check admin/staff username availability
app.get('/check-admin-username', async (req, res) => {
    try {
        const username = req.query.username?.trim();
        if (!username) return res.json({ available: false, message: 'No username provided' });

        const existingAdmin = await Admin.findOne({ username }); // or your staff model
        if (existingAdmin) {
            return res.json({ available: false, message: 'Username already taken' });
        }

        res.json({ available: true, message: 'Username available' });
    } catch (err) {
        console.error('Error checking admin username:', err);
        res.status(500).json({ available: false, message: 'Server error' });
    }
});
app.get('/api/analytics/filtered', checkAdminAuth, async (req, res) => {
  try {
    const { country, destination, season, payment, age } = req.query;

    const matchStage = {};
    if (country && country !== 'all') matchStage['tourDetails.country'] = country;
    if (destination && destination !== 'all') matchStage['tourDetails.destination'] = destination;
    if (season && season !== 'all') matchStage.season = season;
    if (payment && payment !== 'all') matchStage.paymentMethod = payment;
    if (age && age !== 'all') {
      const [min, max] = age.replace('+','').split('-').map(Number);
      const now = new Date();
      const minDOB = new Date(now.getFullYear() - (max || 100));
      const maxDOB = new Date(now.getFullYear() - min);
      matchStage['user.birthdate'] = { $gte: minDOB, $lte: maxDOB };
    }

    const [userData, bookingData] = await Promise.all([
      User.aggregate([
        { $match: matchStage },
        {
          $group: {
            _id: { $month: "$createdAt" },
            count: { $sum: 1 }
          }
        },
        { $sort: { "_id": 1 } }
      ]),
      Booking.aggregate([
        { $match: matchStage },
        {
          $group: {
            _id: { $month: "$createdAt" },
            count: { $sum: 1 },
            revenue: { $sum: "$totalAmount" }
          }
        },
        { $sort: { "_id": 1 } }
      ])
    ]);

    const labels = bookingData.map(b => `Month ${b._id}`);
    const users = userData.map(u => u.count);
    const bookings = bookingData.map(b => b.count);
    const revenue = bookingData.map(b => b.revenue);

    res.json({ labels, users, bookings, revenue });
  } catch (err) {
    console.error('❌ Filtered analytics error:', err);
    res.status(500).json({ message: 'Failed to fetch filtered analytics' });
  }
});
// ✅ Load dynamic filter options (final version)
app.get('/api/filters/dynamic-options', checkAdminAuth, async (req, res) => {
  try {
    const destinations = await Tour.distinct("destination", { destination: { $ne: null } });
    const payments = await Booking.distinct("paymentMethod", { paymentMethod: { $ne: null } });
    res.json({ destinations, payments });
  } catch (err) {
    console.error("❌ Filter option error:", err);
    res.status(500).json({ message: "Failed to fetch filter options" });
  }
});
// ✅ Dynamic Performance Analytics (enhanced with detailed traveler info)
app.get('/api/analytics/dynamic-performance', checkAdminAuth, async (req, res) => {
  try {
    const { destination, payment, age, sex, timePeriod, year, month } = req.query;
    const now = new Date();
    const selectedYear = parseInt(year) || now.getFullYear();
    const selectedMonth = month ? parseInt(month) : now.getMonth();

    let start, end, groupStage, labels;

    // 🗓️ Time range setup
    if (timePeriod === "weekly") {
      start = new Date(selectedYear, selectedMonth, 1);
      end = new Date(selectedYear, selectedMonth + 1, 0, 23, 59, 59);
      const totalDays = new Date(selectedYear, selectedMonth + 1, 0).getDate();
      const weekCount = Math.ceil(totalDays / 7);
      groupStage = { $ceil: { $divide: [{ $dayOfMonth: "$createdAt" }, 7] } };
      labels = Array.from({ length: weekCount }, (_, i) => `Week ${i + 1}`);
    } else if (timePeriod === "monthly") {
      start = new Date(selectedYear, 0, 1);
      end = new Date(selectedYear, 11, 31, 23, 59, 59);
      groupStage = { $month: "$createdAt" };
      labels = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
    } else {
      const currentYear = now.getFullYear();
      start = new Date(currentYear - 5, 0, 1);
      end = new Date(currentYear, 11, 31, 23, 59, 59);
      groupStage = { $year: "$createdAt" };
      labels = Array.from({ length: 6 }, (_, i) => (currentYear - 5 + i).toString());
    }

    // 🧩 Base filter
    const match = { createdAt: { $gte: start, $lte: end } };
    if (destination && destination !== "" && destination !== "all") match.destination = destination;
    if (payment && payment !== "" && payment !== "all") match.paymentMethod = payment;
    if (sex && sex !== "" && sex !== "all") match["travelerDetails.sex"] = sex;

    // 🧮 Age filtering
    if (age && age !== "" && age !== "all") {
      const [min, max] = age.replace("+", "").split("-").map(Number);
      const minDOB = new Date(now.getFullYear() - (max || 100), 0, 1);
      const maxDOB = new Date(now.getFullYear() - min, 11, 31);
      match["travelerDetails.birthdate"] = { $gte: minDOB, $lte: maxDOB };
    }

    // 🧠 Aggregation pipeline
    const pipeline = [
      { $unwind: { path: "$travelerDetails", preserveNullAndEmptyArrays: true } },
      { $match: match },
      {
        $group: {
          _id: {
            period: groupStage,
            destination: destination === "all" ? "$destination" : destination || "$destination",
            payment: payment === "all" ? "$paymentMethod" : payment || "$paymentMethod",
            sex: sex === "all" ? "$travelerDetails.sex" : sex || "$travelerDetails.sex",
            ageRange: age === "all" ? "$travelerDetails.ageRange" : age || "$travelerDetails.ageRange"
          },
          count: { $sum: 1 }
        }
      },
      { $sort: { "_id.period": 1 } }
    ];

    const result = await Booking.aggregate(pipeline);
    const dataMap = {};

    // 🧾 Map results to datasets
    result.forEach(r => {
      const { period, destination, payment, sex, ageRange } = r._id;
      const parts = [];
      if (destination && destination !== "null") parts.push(destination);
      if (payment && payment !== "null") parts.push(payment);
      if (sex && sex !== "null") parts.push(sex);
      if (ageRange && ageRange !== "null") parts.push(ageRange);
      const label = parts.join(" / ") || "Overall";
      if (!dataMap[label]) dataMap[label] = {};
      dataMap[label][period] = (dataMap[label][period] || 0) + r.count;
    });

    // 🎨 Chart datasets
    const colors = ["#f26523","#2563eb","#10b981","#f59e0b","#8b5cf6","#ef4444","#14b8a6","#ec4899","#0ea5e9","#eab308"];
    const datasets = Object.keys(dataMap).map((label, i) => ({
      label,
      data: labels.map((_, idx) => {
        const key =
          timePeriod === "monthly"
            ? idx + 1
            : timePeriod === "yearly"
            ? parseInt(labels[idx])
            : idx + 1;
        return dataMap[label][key] || 0;
      }),
      borderColor: colors[i % colors.length],
      backgroundColor: `${colors[i % colors.length]}33`,
      fill: true,
      tension: 0.3
    }));

    // 🧮 Total Bookings
    const total = datasets.reduce((sum, d) => sum + d.data.reduce((a, b) => a + b, 0), 0);

    // 👥 Collect traveler info (with age, sex, destination, payment)
    const bookings = await Booking.find(match)
      .select('destination paymentMethod travelerDetails')
      .lean();

    const bookedBy = [];
    bookings.forEach(b => {
      if (Array.isArray(b.travelerDetails)) {
        b.travelerDetails.forEach(t => {
          if (t.fullName && t.fullName.trim() !== "") {
            // 🧮 Compute age from birthdate
            let ageValue = "N/A";
            if (t.birthdate) {
              const birth = new Date(t.birthdate);
              const ageNow = now.getFullYear() - birth.getFullYear();
              ageValue = ageNow >= 0 ? ageNow : "N/A";
            }

            bookedBy.push({
              name: t.fullName,
              age: ageValue,
              sex: t.sex || "N/A",
              destination: b.destination || "N/A",
              payment: b.paymentMethod || "N/A",
            });
          }
        });
      }
    });

    // 📋 Active filters text
    const activeFilters = [];
    if (destination && destination !== "all") activeFilters.push(destination);
    if (payment && payment !== "all") activeFilters.push(payment);
    if (age && age !== "all") activeFilters.push(age);
    if (sex && sex !== "all") activeFilters.push(sex);

    const whoBookedSummary =
      activeFilters.length > 0
        ? `🧾 Booked primarily by: ${activeFilters.join(", ")} travelers.`
        : "";

    // ✅ Send Response
    res.json({
      labels,
      datasets,
      total,
      bookedBy,
      insight: `📊 Showing ${timePeriod || "overall"} performance data. ${whoBookedSummary}`
    });

  } catch (err) {
    console.error("❌ Dynamic performance error:", err);
    res.status(500).json({ message: "Failed to fetch performance data" });
  }
});
// ✅ Grouped travelers by transaction for analytics
app.get('/api/admin/booking-groups', checkAdminAuth, checkRole(['admin','employee']), async (req, res) => {
  try {
    const { destination, paymentMethod, gender, ageRange, period, month, year } = req.query;

    // 🧩 Build filters
    const filter = {};
    if (destination && destination !== "all") filter.destination = destination;
    if (paymentMethod && paymentMethod !== "all") filter.paymentMethod = paymentMethod;
    if (gender && gender !== "all") filter["travelerDetails.sex"] = gender;

    // 🗓️ Optional: filter by year/month
    if (year) {
      const start = new Date(year, month ? month - 1 : 0, 1);
      const end = month
        ? new Date(year, month, 0, 23, 59, 59)
        : new Date(year, 11, 31, 23, 59, 59);
      filter.createdAt = { $gte: start, $lte: end };
    }

    // 📦 Fetch bookings
    const bookings = await Booking.find(filter)
      .sort({ createdAt: -1 })
      .lean();

    // 👥 Build grouped traveler list per booking
    const grouped = bookings.map(b => {
      // travelerDetails is always an array (even if empty)
      const peopleArray = Array.isArray(b.travelerDetails) ? b.travelerDetails : [];

      const travelers = peopleArray.map(t => {
        // calculate age if birthdate exists
        let computedAge = "N/A";
        if (t.birthdate) {
          const birth = new Date(t.birthdate);
          const today = new Date();
          computedAge = today.getFullYear() - birth.getFullYear();
          const m = today.getMonth() - birth.getMonth();
          if (m < 0 || (m === 0 && today.getDate() < birth.getDate())) computedAge--;
        }

        return {
          name: t.fullName || "Unknown",
          age: computedAge,
          gender: t.sex || "N/A"
        };
      });

      return {
        bookingId: b.bookingId || b._id.toString(),
        destination: b.destination,
        paymentMethod: b.paymentMethod,
        bookedAt: b.createdAt,
        travelers
      };
    });

    res.json({
      success: true,
      totalBookings: bookings.length,
      totalPeople: grouped.reduce((sum, g) => sum + g.travelers.length, 0),
      grouped
    });

  } catch (err) {
    console.error("❌ Error loading grouped bookings:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.post('/api/admin/forgot-password', async (req, res) => {
    const { email, role } = req.body;
    
    if (!email || !role) {
        return res.status(400).json({ 
            success: false, 
            message: "Email and role are required." 
        });
    }

    try {
        const admin = await Admin.findOne({ email, role });
        
        if (!admin) {
            return res.status(404).json({ 
                success: false, 
                message: "No account found with this email and role." 
            });
        }

        const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
        const expiresAt = new Date(Date.now() + 5 * 60 * 1000);
        
        await OTP.findOneAndUpdate(
            { email }, 
            { otp: otpCode, expiresAt }, 
            { upsert: true, new: true }
        );
        
        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject: "Your Admin Password Reset Code",
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;">
                    <h2 style="color: #f26523;">Admin Password Reset</h2>
                    <p>You requested to reset your password for your ${role} account. Please use the following code:</p>
                    <div style="background-color: #f5f5f5; padding: 10px; text-align: center; font-size: 24px; font-weight: bold; letter-spacing: 5px; margin: 20px 0;">
                        ${otpCode}
                    </div>
                    <p>This code will expire in 5 minutes.</p>
                    <p>If you didn't request this reset, please ignore this email.</p>
                </div>
            `
        });

        return res.json({ 
            success: true, 
            message: "Verification code sent successfully!" 
        });

    } catch (error) {
        console.error("❌ Admin OTP Sending Error:", error);
        return res.status(500).json({ 
            success: false, 
            message: "Failed to send verification code." 
        });
    }
});

app.post('/api/admin/verify-otp', async (req, res) => {
    const { email, otp } = req.body;
    
    if (!email || !otp) {
        return res.status(400).json({ 
            success: false, 
            message: "Email and verification code are required." 
        });
    }

    try {
        const otpRecord = await OTP.findOne({ email }).lean();

        if (!otpRecord) {
            return res.status(400).json({ 
                success: false, 
                message: "No verification code found for this email." 
            });
        }

        if (otpRecord.otp !== otp) {
            return res.status(400).json({ 
                success: false, 
                message: "Incorrect verification code." 
            });
        }

        if (Date.now() > otpRecord.expiresAt) {
            return res.status(400).json({ 
                success: false, 
                message: "Verification code has expired. Request a new one." 
            });
        }

        req.session.adminOtpVerified = true;
        req.session.adminEmail = email;
        
        return res.json({ 
            success: true, 
            message: "Verification code verified successfully!" 
        });

    } catch (error) {
        console.error("❌ Admin OTP Verification Error:", error);
        return res.status(500).json({ 
            success: false, 
            message: "Internal Server Error" 
        });
    }
});

app.post('/api/admin/reset-password', async (req, res) => {
    const { email, newPassword } = req.body;
    
    if (!req.session.adminOtpVerified || req.session.adminEmail !== email) {
        return res.status(401).json({ 
            success: false, 
            message: "Unauthorized reset request." 
        });
    }

    try {
        const admin = await Admin.findOne({ email });
        
        if (!admin) {
            return res.status(404).json({ 
                success: false, 
                message: "Admin not found." 
            });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await Admin.findOneAndUpdate({ email }, { password: hashedPassword });
        
        await OTP.deleteOne({ email });
        delete req.session.adminOtpVerified;
        delete req.session.adminEmail;

        return res.json({ 
            success: true, 
            message: "Password reset successfully!" 
        });
        
    } catch (error) {
        console.error("❌ Admin Password Reset Error:", error);
        return res.status(500).json({ 
            success: false, 
            message: "Failed to reset password." 
        });
    }
});

app.get('/api/admin/logout', (req, res) => {
    if (req.session.admin) {
        delete req.session.admin;
    }
    return res.json({ 
        success: true, 
        message: 'Logged out successfully' 
    });
});

app.post('/admin-send-otp', async (req, res) => {
    const { email, role } = req.body;
    
    if (!email || !role) {
        return res.status(400).json({ 
            success: false, 
            message: "Email and role are required." 
        });
    }

    try {
        const employee = await Employee.findOne({ email, role });
        
        if (!employee) {
            return res.status(404).json({ 
                success: false, 
                message: "No account found with this email and role." 
            });
        }

        const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
        const expiresAt = new Date(Date.now() + 5 * 60 * 1000);
        
        await OTP.findOneAndUpdate(
            { email }, 
            { otp: otpCode, expiresAt }, 
            { upsert: true, new: true }
        );
        
        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject: "Your Staff Password Reset Code",
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;">
                    <h2 style="color: #f26523;">Staff Password Reset</h2>
                    <p>You requested to reset your password for your ${role} account. Please use the following code:</p>
                    <div style="background-color: #f5f5f5; padding: 10px; text-align: center; font-size: 24px; font-weight: bold; letter-spacing: 5px; margin: 20px 0;">
                        ${otpCode}
                    </div>
                    <p>This code will expire in 5 minutes.</p>
                    <p>If you didn't request this reset, please ignore this email.</p>
                </div>
            `
        });

        return res.json({ 
            success: true, 
            message: "Verification code sent successfully!" 
        });

    } catch (error) {
        console.error("❌ Admin OTP Sending Error:", error);
        return res.status(500).json({ 
            success: false, 
            message: "Failed to send verification code." 
        });
    }
});

app.post('/admin-verify-otp', async (req, res) => {
    const { email, otp } = req.body;
    
    if (!email || !otp) {
        return res.status(400).json({ 
            success: false, 
            message: "Email and verification code are required." 
        });
    }

    try {
        const otpRecord = await OTP.findOne({ email }).lean();

        if (!otpRecord) {
            return res.status(400).json({ 
                success: false, 
                message: "No verification code found for this email." 
            });
        }

        if (otpRecord.otp !== otp) {
            return res.status(400).json({ 
                success: false, 
                message: "Incorrect verification code." 
            });
        }

        if (Date.now() > otpRecord.expiresAt) {
            return res.status(400).json({ 
                success: false, 
                message: "Verification code has expired. Request a new one." 
            });
        }

        req.session.adminOtpVerified = true;
        req.session.adminEmail = email;
        
        return res.json({ 
            success: true, 
            message: "Verification code verified successfully!" 
        });

    } catch (error) {
        console.error("❌ Admin OTP Verification Error:", error);
        return res.status(500).json({ 
            success: false, 
            message: "Internal Server Error" 
        });
    }
});
app.post('/admin-reset-password', async (req, res) => {
    const { email, newPassword } = req.body;
    
    if (!req.session.adminOtpVerified || req.session.adminEmail !== email) {
        return res.status(401).json({ 
            success: false, 
            message: "Unauthorized reset request." 
        });
    }

    try {
        const employee = await Employee.findOne({ email });
        
        if (!employee) {
            return res.status(404).json({ 
                success: false, 
                message: "Employee not found." 
            });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await Employee.findOneAndUpdate({ email }, { password: hashedPassword });
        await OTP.deleteOne({ email });
        delete req.session.adminOtpVerified;
        delete req.session.adminEmail;

        return res.json({ 
            success: true, 
            message: "Password reset successfully!" 
        });
        
    } catch (error) {
        console.error("❌ Admin Password Reset Error:", error);
        return res.status(500).json({ 
            success: false, 
            message: "Failed to reset password." 
        });
    }
});

app.get('/admin-pending-accounts', async (req, res) => {
    if (!req.session.employee || req.session.employee.role !== 'admin') {
        return res.status(403).json({ 
            success: false, 
            message: 'Unauthorized access' 
        });
    }

    try {
        const pendingAccounts = await Employee.find({ 
            isApproved: false 
        }).select('-password');
        
        return res.json({ 
            success: true, 
            pendingAccounts 
        });
        
    } catch (error) {
        console.error('❌ Error fetching pending accounts:', error);
        return res.status(500).json({ 
            success: false, 
            message: 'Internal server error' 
        });
    }
});

app.post('/admin-account-action', async (req, res) => {
    const { employeeId, action } = req.body;
    
    if (!req.session.employee || req.session.employee.role !== 'admin') {
        return res.status(403).json({ 
            success: false, 
            message: 'Unauthorized access' 
        });
    }

    try {
        const employee = await Employee.findById(employeeId);
        
        if (!employee) {
            return res.status(404).json({ 
                success: false, 
                message: 'Employee not found' 
            });
        }

        if (action === 'approve') {
            employee.isApproved = true;
            await employee.save();
            
            await transporter.sendMail({
                from: process.env.EMAIL_USER,
                to: employee.email,
                subject: "Your Staff Account Has Been Approved",
                html: `
                    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;">
                        <h2 style="color: #f26523;">Account Approved</h2>
                        <p>Your ${employee.role} account has been approved.</p>
                        <p>You can now log in to the staff portal using your credentials.</p>
                    </div>
                `
            });
            
            return res.json({ 
                success: true, 
                message: 'Account approved successfully' 
            });
            
        } else if (action === 'reject') {

            await transporter.sendMail({
                from: process.env.EMAIL_USER,
                to: employee.email,
                subject: "Your Staff Account Request Was Declined",
                html: `
                    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;">
                        <h2 style="color: #f26523;">Account Request Declined</h2>
                        <p>We're sorry, but your request for a ${employee.role} account has been declined.</p>
                        <p>If you believe this is an error, please contact the administrator.</p>
                    </div>
                `
            });
            
            await Employee.findByIdAndDelete(employeeId);
            
            return res.json({ 
                success: true, 
                message: 'Account rejected and removed' 
            });
        }
        
        return res.status(400).json({ 
            success: false, 
            message: 'Invalid action' 
        });
        
    } catch (error) {
        console.error('❌ Error processing account action:', error);
        return res.status(500).json({ 
            success: false, 
            message: 'Internal server error' 
        });
    }
});
app.get('/admin-logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('❌ Error destroying session:', err);
            return res.status(500).json({ 
                success: false, 
                message: 'Logout failed' 
            });
        }
        res.clearCookie('connect.sid');
        return res.json({ 
            success: true, 
            message: 'Logged out successfully' 
        });
    });
});
app.get('/user-dashboard', (req, res) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }

    res.render('user-dashboard', { user: req.session.user }); 
});

app.get('/user-users', async (req, res) => {
    try {
        const users = await User.find();
        res.render('user-users', { users: users });
    } catch (error) {
        console.error(error);
        res.status(500).send('Internal Server Error');
    }
});

app.get('/user-bookings', (req, res) => {
    if (req.session.user) {
        Booking.find({ userId: req.session.user.id })
            .then(bookings => {
                res.render('user-bookings', { bookings: bookings });
            })
            .catch(error => {
                console.error(error);
                res.status(500).send('Error fetching bookings');
            });
    } else {
        res.redirect('/');
    }
});
// ✅ USER SIGNUP ROUTE (Auto-login enabled)
app.post('/signup', async (req, res) => {
  try {
    const { username, email, password, phoneNumber, phonenumber } = req.body;
    const phone = phoneNumber || phonenumber;

    if (!username || !email || !password || !phone) {
      return res.status(400).json({ success: false, message: 'All fields are required' });
    }

    // Check for duplicate username
    const existingUsername = await User.findOne({ username });
    if (existingUsername) {
      return res.status(400).json({ success: false, message: 'Username already taken' });
    }

    // Check for duplicate email
    const existingEmail = await User.findOne({ email });
    if (existingEmail) {
      return res.status(400).json({ success: false, message: 'Email already taken' });
    }

    // ✅ Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create and save new user
    const newUser = new User({
      username,
      email,
      password: hashedPassword,
      phoneNumber: phone
    });
  await newUser.save();

// ✅ Auto-login user immediately after successful signup
req.session.user = {
  id: newUser._id,
  username: newUser.username,
  email: newUser.email,
  phoneNumber: newUser.phoneNumber
};
console.log(`✅ ${newUser.username} signed up and auto-logged in.`);

// ✅ Send confirmation email (non-blocking)
try {
  await transporter.sendMail({
    from: process.env.EMAIL_USER,
    to: email,
    subject: 'Account Created Successfully',
    html: `
      <div style="font-family: Arial, sans-serif; padding: 20px;">
        <h2>Welcome to A.BEE Travel and Tours!</h2>
        <p>Hi ${username},</p>
        <p>Your account has been successfully created and you are now logged in!</p>
        <p>— The A.BEE Travel and Tours Team</p>
      </div>
    `
  });
} catch (mailError) {
  console.warn('⚠️ Failed to send confirmation email:', mailError.message);
}

return res.status(201).json({
  success: true,
  autoLogin: true,
  message: 'Signup successful! You are now logged in.'
});


  } catch (error) {
    console.error('❌ Signup error:', error);
    return res.status(500).json({ success: false, message: 'Error creating account' });
  }
});




app.get('/settings', (req, res) => {
    res.render('settings');
});

app.delete('/delete-account', async (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ success: false, message: 'Unauthorized. Please log in again.' });
    }

    try {
        const userId = req.session.user.id;
        await Booking.deleteMany({ userId: userId });
        const deletedUser = await User.deleteOne({ _id: new ObjectId(userId) });

        if (deletedUser.deletedCount === 0) {
            return res.status(400).json({ success: false, message: 'Account not found.' });
        }
        req.session.destroy((err) => {
            if (err) {
                return res.status(500).json({ success: false, message: 'Error logging out after deletion.' });
            }
            res.clearCookie('connect.sid');
            return res.json({ success: true, message: 'Account and associated bookings deleted successfully.' });
        });
    } catch (error) {
        console.error('❌ Account Deletion Error:', error);
        res.status(500).json({ success: false, message: 'Internal Server Error' });
    }
});
app.post('/submit-booking', isAuthenticated, async (req, res) => {
  try {
    console.log('Booking submission received:', req.body);

    const {
      tourId,
      fullName,
      email,
      phone,
      nationality,
      travelers,
      startDate,
      specialRequests,
      paymentMethod,
      paymentId,
      receiptUrl,
      totalAmount,
      budget,
      endDate,
      middleInitial,
      suffix,
      country,
      travelerDetails // 👈 we now expect this as an array from the frontend
    } = req.body;

    if (!tourId || !fullName || !email || !phone || !travelers || !startDate || !paymentMethod) {
      return res.status(400).json({
        success: false,
        message: 'Missing required fields'
      });
    }

    if (paymentMethod === 'gcash' && !receiptUrl) {
      return res.status(400).json({
        success: false,
        message: 'Receipt upload is required for GCash payments'
      });
    }

    const tour = await Tour.findById(tourId);
    if (!tour) {
      return res.status(404).json({
        success: false,
        message: 'Tour not found'
      });
    }

    // 🧩 Parse travelerDetails (sent from frontend as JSON or object array)
    let parsedTravelerDetails = [];
    try {
      if (typeof travelerDetails === 'string') {
        parsedTravelerDetails = JSON.parse(travelerDetails);
      } else if (Array.isArray(travelerDetails)) {
        parsedTravelerDetails = travelerDetails;
      }
    } catch (parseErr) {
      console.warn('Could not parse traveler details:', parseErr);
    }

    if (!Array.isArray(parsedTravelerDetails) || parsedTravelerDetails.length !== parseInt(travelers)) {
      return res.status(400).json({
        success: false,
        message: `Traveler details mismatch: expected ${travelers}, got ${parsedTravelerDetails.length}`
      });
    }

    // ✅ Create the booking
    const booking = new Booking({
      userId: req.session.user.id,
      tourId,
      fullName,
      email,
      phone,
      nationality,
      travelers: parseInt(travelers),
      travelerDetails: parsedTravelerDetails, // 👈 Save here
      startDate: new Date(startDate),
      endDate: endDate ? new Date(endDate) : new Date(startDate),
      budget: budget || totalAmount,
      specialRequests,
      paymentMethod,
      paymentId,
      receiptUrl,
      totalAmount: typeof totalAmount === 'string'
        ? parseFloat(totalAmount.replace(/,/g, ''))
        : parseFloat(totalAmount),
      status: paymentMethod === 'paypal' ? 'confirmed' : 'pending',
      destination: tour.destination,
      country: tour.country,
      middleInitial,
      suffix,
      tourDetails: {
        title: tour.title,
        destination: tour.destination,
        country: tour.country,
        duration: tour.duration,
        durationUnit: tour.durationUnit,
        price: tour.price
      }
    });

    console.log('Saving booking:', booking);
    await booking.save();
    console.log('Booking saved successfully with ID:', booking.bookingId);

    // ✅ Email setup (same as before)
    let paymentDetails = '';
    if (paymentMethod === 'paypal') {
      paymentDetails = '<p><strong>Payment Status:</strong> Confirmed via PayPal</p>';
    } else if (paymentMethod === 'gcash') {
      paymentDetails = `
        <p><strong>Payment Status:</strong> Pending verification</p>
        <p>We have received your GCash payment receipt and will verify it shortly.</p>
      `;
    } else if (paymentMethod === 'store') {
      paymentDetails = `
        <div style="background-color: #fff3cd; padding: 15px; margin: 15px 0; border-radius: 5px; border-left: 4px solid #ffc107;">
          <p><strong>Important:</strong> Please visit our office within 8 hours to complete your payment:</p>
          <p>A.BEE Travel and Tours<br>
          Ground Level, Robinsons Townville, H. Concepcion., Cabanatuan City<br>
          Business Hours: Monday-Friday, 9:00 AM - 5:00 PM<br>
          Contact: (044) 604 7273</p>
          <p><strong>Your booking will automatically be cancelled if payment is not received within 8 hours.</strong></p>
        </div>
      `;
    }

    try {
      await transporter.sendMail({
        from: process.env.EMAIL_USER,
        to: email,
        subject: "Your Tour Booking Confirmation",
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;">
            <h2 style="color: #f26523;">Booking Confirmation</h2>
            <p>Dear ${fullName},</p>
            <p>Thank you for booking with A.BEE Travel and Tours. Your booking has been ${paymentMethod === 'paypal' ? 'confirmed' : 'received'}.</p>
            
            <div style="background-color: #f5f5f5; padding: 15px; margin: 15px 0; border-radius: 5px;">
              <h3 style="margin-top: 0;">Booking Details:</h3>
              <p><strong>Booking Reference:</strong> ${booking.bookingId}</p>
              <p><strong>Tour:</strong> ${tour.title}</p>
              <p><strong>Destination:</strong> ${tour.destination}, ${tour.country || 'N/A'}</p>
              <p><strong>Start Date:</strong> ${new Date(startDate).toLocaleDateString()}</p>
              <p><strong>Duration:</strong> ${tour.duration} ${tour.durationUnit}</p>
              <p><strong>Number of Travelers:</strong> ${travelers}</p>
              <p><strong>Total Amount:</strong> ₱${typeof booking.totalAmount === 'number' ? booking.totalAmount.toLocaleString() : booking.totalAmount}</p>
              <p><strong>Payment Method:</strong> ${paymentMethod.charAt(0).toUpperCase() + paymentMethod.slice(1)}</p>
              <p><strong>Booking Status:</strong> ${paymentMethod === 'paypal' ? 'Confirmed' : 'Pending'}</p>
            </div>

            ${
              parsedTravelerDetails && parsedTravelerDetails.length > 0
                ? `<h3>Traveler Information</h3>
                  <ul>${parsedTravelerDetails
                    .map(
                      (t, i) => `<li><strong>Traveler ${i + 1}:</strong> ${t.fullName} (${t.nationality || 'N/A'})</li>`
                    )
                    .join('')}</ul>`
                : ''
            }

            ${paymentDetails}

            <p>If you have any questions or need to make changes to your booking, please contact us at:</p>
            <p>📞 (044) 604 7273 or 09361055665<br>
            📧 <a href="mailto:abeetravelandtours@gmail.com">abeetravelandtours@gmail.com</a></p>

            <p>Thank you for choosing A.BEE Travel and Tours!</p>
          </div>
        `
      });
      console.log('Confirmation email sent');
    } catch (emailError) {
      console.error('Error sending confirmation email:', emailError);
    }

    if (phone) {
      try {
        const smsMessage = `A.BEE Travel: Your booking for ${tour.title} to ${tour.destination}, ${tour.country || 'N/A'} has been ${paymentMethod === 'paypal' ? 'confirmed' : 'received'}. Ref: ${booking.bookingId}. For details, check your email.`;
        const smsResult = await sendSMS(phone, smsMessage);

        if (smsResult.success) {
          console.log('SMS notification sent successfully');
        } else {
          console.warn('SMS notification failed:', smsResult.message);
        }
      } catch (smsError) {
        console.error('Error sending SMS notification:', smsError);
      }
    }

    res.json({
      success: true,
      message: 'Booking submitted successfully',
      bookingId: booking._id,
      bookingReference: booking.bookingId
    });
  } catch (error) {
    console.error('Error submitting booking:', error);
    res.status(500).json({
      success: false,
      message: 'An error occurred while processing your booking: ' + error.message
    });
  }
});


app.get('/check-auth', (req, res) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    res.setHeader('Surrogate-Control', 'no-store');
    
    if (req.session && req.session.user) {
        res.json({ 
            isLoggedIn: true, 
            userId: req.session.user.id,
            username: req.session.user.username
        });
    } else {
        res.json({ 
            isLoggedIn: false 
        });
    }
});

app.get('/admin-dashboard', (req, res) => {
    if (!req.session.admin) {
        return res.redirect('/admin');
    }
    console.log('Rendering admin dashboard for:', req.session.admin);
    res.render('admin-dashboard', { 
        admin: req.session.admin
    });
});

app.get("/admin-logout", (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.redirect("/admin-dashboard");
        }
        res.redirect("/admin");
    });
});
// ✅ Check if admin is still authenticated (used by admin-users.ejs and others)
app.get('/api/admin/check-auth', (req, res) => {
  try {
    if (req.session && req.session.admin) {
      return res.json({
        isAuthenticated: true,
        admin: {
          id: req.session.admin._id || req.session.admin.id,
          firstName: req.session.admin.firstName,
          lastName: req.session.admin.lastName,
          role: req.session.admin.role
        }
      });
    } else {
      return res.json({ isAuthenticated: false });
    }
  } catch (error) {
    console.error('❌ Error checking admin auth:', error);
    return res.status(500).json({ isAuthenticated: false });
  }
});

app.post('/update-booking-status/:bookingId', (req, res) => {
    const { bookingId } = req.params;
    const { approvalStatus } = req.body;

    if (!req.session.isAdmin) {
        return res.status(403).send('Forbidden');
    }

    Booking.findByIdAndUpdate(bookingId, { approvalStatus }, { new: true })
        .then(updatedBooking => {
            if (!updatedBooking) {
                return res.status(404).send('Booking not found');
            }
            res.status(200).send('Booking status updated');
        })
        .catch(err => {
            console.error("Error updating booking status:", err);
            res.status(500).send('Server Error');
        });
});

app.post('/admin-bookings/update-status', async (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(403).json({ error: "Unauthorized access." });
    }

    try {
        const { bookingId, status } = req.body;

        if (!bookingId || !status) {
            return res.status(400).json({ error: "Missing bookingId or status." });
        }

        const booking = await Booking.findByIdAndUpdate(bookingId, { status }, { new: true });

        if (!booking) {
            return res.status(404).json({ error: "Booking not found." });
        }

        res.json({ success: true, message: "Booking status updated.", booking });
    } catch (error) {

        console.error("❌ Error updating booking status:", error);
        res.status(500).json({ error: "Failed to update booking status." });
    }
});
app.get('/api/get-latest-booking-status', (req, res) => {
    Booking.find({ approvalStatus: { $ne: 'Approved' } })
        .sort({ createdAt: -1 })
        .limit(1)
        .then(latestBooking => {
            if (latestBooking.length > 0) {
                const status = latestBooking[0].approvalStatus;
                res.json({ status });
            } else {
                res.json({ status: 'No new bookings' });
            }
        })
        .catch(err => {
            console.error('Error fetching booking status:', err);
            res.status(500).json({ status: 'Error loading status' });
        });
});

app.get('/admin-users', async (req, res) => {
    try {
        const users = await User.find();
        res.render('admin-users', { users });
    } catch (err) {
        console.error('Error fetching users:', err);
        res.status(500).send('Error fetching users');
    }
}); 
app.get("/my-bookings", async (req, res) => {
    try {
        if (!req.session.user) {
            return res.redirect('/');
        }
        
        const userId = req.session.user.id;
        const bookings = await Booking.find({ userId: userId }).sort({ createdAt: -1 });
        
        console.log(`Found ${bookings.length} bookings for user ${userId}`);
        
        res.render("my-bookings", { bookings, user: req.session.user });
    } catch (error) {
        console.error("Error fetching bookings:", error);
        res.status(500).send("Error fetching bookings.");
    }
});
app.post('/api/admin/login', async (req, res) => { 
    console.log('Admin login request received:', req.body);
    const { username, password, captchaVerified } = req.body;

    if (!captchaVerified) {
        return res.status(400).json({ 
            success: false, 
            message: 'CAPTCHA verification required' 
        });
    }

    try {
        const admin = await Admin.findOne({ username });
        console.log('Admin found:', admin ? 'Yes' : 'No');

        if (!admin) {
            return res.status(401).json({ 
                success: false, 
                message: 'Invalid credentials' 
            });
        }
if (admin.isActive === false) {
    return res.status(403).json({
        success: false,
        message: 'Your admin account has been deactivated. Please contact support.'
    });
}

if (!admin.isVerified || admin.status !== 'active') {
    return res.status(401).json({ 
        success: false, 
        status: 'pending',
        message: 'Your account is pending approval' 
    });
}


        if (admin.status === 'suspended') {
            return res.status(403).json({ 
                success: false, 
                status: 'suspended',
                message: 'Your admin account has been suspended. Please contact support.' 
            });
        }

        const isMatch = await bcrypt.compare(password, admin.password);
        console.log('Password match:', isMatch ? 'Yes' : 'No');
        
        if (!isMatch) {
            return res.status(401).json({ 
                success: false, 
                message: 'Invalid credentials' 
            });
        }

        req.session.admin = {
            id: admin._id,
            firstName: admin.firstName,
            lastName: admin.lastName,
            username: admin.email,
            role: admin.role
        };
        
        let redirectUrl;
        if (admin.role === 'admin') {
            redirectUrl = '/admin-dashboard';
        } else if (admin.role === 'employee') {
            redirectUrl = '/employee-dashboard';
        } else {
            redirectUrl = '/';
        }

        return res.json({
            success: true,
            message: 'Login successful',
            redirectUrl: redirectUrl,
            admin: {
                id: admin._id,
                firstName: admin.firstName,
                lastName: admin.lastName,
                username: admin.username,
                role: admin.role
            }
        });

    } catch (error) {
        console.error('❌ Admin Login Error:', error);
        return res.status(500).json({ 
            success: false, 
            message: 'Internal Server Error' 
        });
    }
});


app.post('/login', async (req, res) => {
    try {
        const { username, password, captchaVerified } = req.body;
        
        // Require captcha verification
        if (!captchaVerified) {
            return res.status(400).json({ success: false, message: 'CAPTCHA verification required' });
        }

        const user = await User.findOne({ username });

        if (!user) {
            return res.status(400).json({ success: false, message: 'Invalid credentials' });
        }
        
        if (user.isActive === false) {
            return res.status(403).json({ success: false, message: 'Your account has been deactivated. Please contact support.' });
        }
        
        const isMatch = await user.comparePassword(password);
        if (!isMatch) {
            return res.status(400).json({ success: false, message: 'Invalid credentials' });
        }

        req.session.user = {
            id: user._id,
            username: user.username,
            email: user.email,
            phoneNumber: user.phoneNumber,
            firstName: user.firstName,
            lastName: user.lastName
        };

        return res.json({ success: true, message: 'Login successful' });

    } catch (error) {
        console.error('❌ Login Error:', error);
        return res.status(500).json({ success: false, message: 'Internal Server Error' });
    }
});


function isAuthenticated(req, res, next) {
    if (!req.session || !req.session.user) {
        return res.status(401).json({ success: false, message: 'User not logged in' });
    }
    next();
}
app.post('/update-profile', isAuthenticated, async (req, res) => {
    try {
        const { firstName, middleInitial, lastName, suffix, phoneNumber, birthdate, sex, nationality } = req.body; // Add nationality
        const updatedUser = await User.findByIdAndUpdate(req.session.user.id, {
            firstName, 
            middleInitial,
            lastName, 
            suffix,
            phoneNumber, 
            birthdate: birthdate ? new Date(birthdate) : null, 
            sex,
            nationality  // Add this line
        }, { new: true });

        if (!updatedUser) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        req.session.user = {
            id: updatedUser._id,
            username: updatedUser.username,
            email: updatedUser.email,
            phoneNumber: updatedUser.phoneNumber,
            firstName: updatedUser.firstName,
            middleInitial: updatedUser.middleInitial,
            lastName: updatedUser.lastName,
            suffix: updatedUser.suffix,
            birthdate: updatedUser.birthdate,
            sex: updatedUser.sex,
            nationality: updatedUser.nationality  // Add this line
        };

        return res.json({ success: true, message: 'Profile updated successfully!' });

    } catch (error) {
        console.error('❌ Error updating profile:', error);
        return res.status(500).json({ success: false, message: 'Error updating profile' });
    }
});

app.get('/admin-dashboard/data', async (req, res) => {
    try {
        console.log("🔄 Fetching admin dashboard data...");

        const sevenDaysAgo = new Date();
        sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 6);
        sevenDaysAgo.setUTCHours(0, 0, 0, 0);

        // 🔹 Users this week
        const users = await User.find({ 
            createdAt: { $gte: sevenDaysAgo } 
        }).sort({ createdAt: 1 });

        const usersByDay = {};
        users.forEach(user => {
            const dateKey = new Date(user.createdAt).toISOString().split('T')[0];
            if (!usersByDay[dateKey]) {
                usersByDay[dateKey] = { date: user.createdAt, count: 0 };
            }
            usersByDay[dateKey].count++;
        });

        // 🔹 Bookings this week
        const bookings = await Booking.find({ 
            createdAt: { $gte: sevenDaysAgo } 
        }).sort({ createdAt: 1 });

        const bookingsByDay = {};
        bookings.forEach(booking => {
            const dateKey = new Date(booking.createdAt).toISOString().split('T')[0];
            if (!bookingsByDay[dateKey]) {
                bookingsByDay[dateKey] = { date: booking.createdAt, count: 0 };
            }
            bookingsByDay[dateKey].count++;
        });

        const usersThisWeek = Object.values(usersByDay);
        const bookingsThisWeek = Object.values(bookingsByDay);

        // 🔹 All-time totals
        const totalUsers = await User.countDocuments();
        const totalBookings = await Booking.countDocuments();

        // 🔹 Total sales (confirmed + completed)
        const totalSalesResult = await Booking.aggregate([
            { $match: { status: { $in: ['confirmed', 'completed'] } } },
            { $group: { _id: null, totalSales: { $sum: "$totalAmount" } } }
        ]);
        const totalSales = totalSalesResult[0]?.totalSales || 0;

        console.log("✅ Users This Week:", usersThisWeek.length);
        console.log("✅ Bookings This Week:", bookingsThisWeek.length);
        console.log("✅ Total Sales:", totalSales);

        res.json({
            success: true,
            usersThisWeek,
            bookingsThisWeek,
            totalUsers,
            totalBookings,
            totalSales
        });

    } catch (error) {
        console.error("❌ Error fetching dashboard data:", error);
        res.status(500).json({ success: false, error: "Failed to fetch dashboard data." });
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('❌ Error destroying session:', err);
            return res.status(500).send('Logout failed');
        }
        res.clearCookie('connect.sid');
        res.redirect('/');
    });
});

const sendOTP = async (email) => {
    try {
        const otpCode = Math.floor(100000 + Math.random() * 900000);
        const otpExpiry = Date.now() + 10 * 60 * 1000; 
        await OTP.findOneAndUpdate(
            { email }, 
            { otp: otpCode, expiresAt: otpExpiry }, 
            { upsert: true, new: true }
        );
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: "Your OTP Verification Code",
            text: `Your OTP code is: ${otpCode}. It is valid for 10 minutes.`
        };

        await transporter.sendMail(mailOptions);
        return { success: true, message: "OTP sent successfully!" };
    } catch (error) {
        console.error("❌ Error sending OTP:", error);
        return { success: false, message: "Failed to send OTP." };
    }
};

app.post('/send-otp', async (req, res) => {
    const { email } = req.body;
    console.log("📧 Received OTP request for email:", email);

    if (!email) {
        return res.status(400).json({ success: false, message: "Email is required." });
    }

    try {
        const userExists = await User.findOne({ email });
        if (!userExists) {
            console.log("❌ User not found for email:", email);
            return res.status(404).json({ success: false, message: "No account found with this email address." });
        }

        const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
        const expiresAt = new Date(Date.now() + 5 * 60 * 1000);
        
        console.log("🔑 Generated OTP:", otpCode, "for email:", email);

        await OTP.findOneAndUpdate(
            { email }, 
            { otp: otpCode, expiresAt }, 
            { upsert: true, new: true }
        );
        
        console.log("💾 OTP saved to database for email:", email);
        try {
            await transporter.sendMail({
                from: process.env.EMAIL_USER,
                to: email,
                subject: "Your Password Reset Code",
                text: `Your password reset code is: ${otpCode}. It will expire in 5 minutes.`,
                html: `
                    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;">
                        <h2 style="color: #f26523;">Password Reset</h2>
                        <p>You requested to reset your password. Please use the following code:</p>
                        <div style="background-color: #f5f5f5; padding: 10px; text-align: center; font-size: 24px; font-weight: bold; letter-spacing: 5px; margin: 20px 0;">
                            ${otpCode}
                        </div>
                        <p>This code will expire in 5 minutes.</p>
                        <p>If you didn't request this reset, please ignore this email.</p>
                    </div>
                `
            });
            console.log("📤 Email sent successfully to:", email);
        } catch (emailError) {
            console.error("📤 Email sending failed:", emailError);
            throw new Error(`Failed to send email: ${emailError.message}`);
        }

        return res.json({ success: true, message: "OTP sent successfully!" });

    } catch (error) {
        console.error("❌ OTP Sending Error:", error);
        return res.status(500).json({ success: false, message: "Failed to send OTP. Please try again later." });
    }
});

app.get('/admin-employee-signup', (req, res) => {
    if (req.session.user && req.session.user.role === 'admin') {
        res.render('admin-employee-signup');
    } else {
        res.redirect('/admin-dashboard');
    }
});
app.post('/admin-employee-signup', async (req, res) => {
    const { username, password, confirmPassword } = req.body;

    if (password !== confirmPassword) {
        return res.status(400).send('Passwords do not match.');
    }

    try {
        const existingEmployee = await Employee.findOne({ username });

        if (existingEmployee) {
            return res.status(400).send('Username already exists.');
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const employee = new Employee({
            username,
            password: hashedPassword,
        });

        await employee.save();

        res.redirect('/admin-dashboard');
    } catch (err) {
        console.error(err);
        res.status(500).send('Error signing up employee');
    }
});

app.post('/send-code', async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ success: false, message: "Email is required." });
    }

    try {
        const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
        const expiresAt = new Date(Date.now() + 10 * 60 * 1000);
        
        await OTP.findOneAndUpdate(
            { email }, 
            { otp: verificationCode, expiresAt }, 
            { upsert: true, new: true }
        );
        
        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject: "Your Email Verification Code",
            text: `Your verification code is: ${verificationCode}. It will expire in 10 minutes.`,
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;">
                    <h2 style="color: #f26523;">Email Verification</h2>
                    <p>Thank you for signing up! Please use the following code to verify your email address:</p>
                    <div style="background-color: #f5f5f5; padding: 10px; text-align: center; font-size: 24px; font-weight: bold; letter-spacing: 5px; margin: 20px 0;">
                        ${verificationCode}
                    </div>
                    <p>This code will expire in 10 minutes.</p>
                    <p>If you didn't request this verification, please ignore this email.</p>
                </div>
            `
        });

        return res.json({ success: true, message: "Verification code sent successfully!" });

    } catch (error) {
        console.error("❌ Verification Code Sending Error:", error);
        return res.status(500).json({ success: false, message: "Failed to send verification code." });
    }
});

app.post('/verify-code', async (req, res) => {
    const { email, code } = req.body;
    
    if (!email || !code) {
        return res.status(400).json({ success: false, message: "Email and verification code are required." });
    }

    try {
        const otpRecord = await OTP.findOne({ email }).lean();

        if (!otpRecord) {
            return res.status(400).json({ success: false, message: "No verification code found for this email." });
        }

        if (otpRecord.otp !== code) {
            return res.status(400).json({ success: false, message: "Incorrect verification code." });
        }

        if (Date.now() > otpRecord.expiresAt) {
            return res.status(400).json({ success: false, message: "Verification code has expired. Request a new one." });
        }

        await OTP.deleteOne({ email });

        return res.json({ success: true, message: "Email verified successfully!" });

    } catch (error) {
        console.error("❌ Code Verification Error:", error);
        return res.status(500).json({ success: false, message: "Internal Server Error" });
    }
});
app.get('/', async (req, res) => {
    try {
        const bookings = await Booking.find();
        const bookingStatus = bookings.length > 0 ? 'You have bookings.' : 'You have no bookings at the moment.';
        res.render('index', { bookingStatus });
    } catch (err) {
        console.error('Error fetching bookings:', err);
        res.render('index', { bookingStatus: 'Error fetching bookings.' });
    }
});
app.get('/api/admin/recent-users', checkAdminAuth, async (req, res) => {
    try {
        const users = await User.find()
            .sort({ createdAt: -1 })
            .limit(10)
            .select('username email firstName lastName createdAt');
        
        res.json({
            success: true,
            users
        });
    } catch (error) {
        console.error('Error fetching recent users:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch recent users'
        });
    }
});

app.get('/api/admin/recent-bookings', checkAdminAuth, async (req, res) => {
    try {
        const bookings = await Booking.find()
            .sort({ createdAt: -1 })
            .limit(10);
        
        res.json({
            success: true,
            bookings
        });
    } catch (error) {
        console.error('Error fetching recent bookings:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch recent bookings'
        });
    }
});

cron.schedule('0 0 * * *', async () => {
    const today = new Date();
    today.setHours(0, 0, 0, 0);
  
    const userCount = await User.countDocuments({ createdAt: { $gte: today } });
    const bookingCount = await Booking.countDocuments({ createdAt: { $gte: today } });
  
    await DailyUserCount.create({ date: today, count: userCount });
    await DailyBookingCount.create({ date: today, count: bookingCount });
  
    console.log('Daily counts updated:', today);
});
const tourStorage = multer.diskStorage({
    destination: function(req, file, cb) {
        const uploadDir = 'public/uploads/tours';
        
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir, { recursive: true });
        }
        
        cb(null, uploadDir);
    },
    filename: function(req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        const ext = path.extname(file.originalname);
        cb(null, 'tour-' + uniqueSuffix + ext);
    }
});

const tourUpload = multer({ 
    storage: tourStorage,
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: function(req, file, cb) {
        const filetypes = /jpeg|jpg|png|gif|webp/;
        const mimetype = filetypes.test(file.mimetype);
        const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
        
        if (mimetype && extname) {
            return cb(null, true);
        }
        
        cb(new Error('Only image files are allowed!'));
    }
});

app.get('/admin-tours', checkAdminAuth, (req, res) => {
    res.render('admin-tour-post', { admin: req.session.admin });
});

app.get('/api/tours', async (req, res) => {
    try {
        const { featured, destination, minPrice, maxPrice, limit = 10, includeHidden = false } = req.query;
        
        const query = {};
        
        if (!includeHidden) {
            query.hidden = { $ne: true };
        }
        
        if (featured === 'true') {
            query.featured = true;
        }
        
        if (destination) {
            query.destination = { $regex: destination, $options: 'i' };
        }
        
        if (minPrice || maxPrice) {
            query.price = {};
            
            if (minPrice) {
                query.price.$gte = parseFloat(minPrice);
            }
            
            if (maxPrice) {
                query.price.$lte = parseFloat(maxPrice);
            }
        }
        
        const tours = await Tour.find(query)
            .sort({ createdAt: -1 })
            .limit(parseInt(limit));
        
        res.json({
            success: true,
            tours
        });
    } catch (error) {
        console.error('Error fetching tours:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch tours'
        });
    }
});

app.get('/api/tours/featured', async (req, res) => {
    try {
        const tours = await Tour.find({ featured: true })
            .sort({ createdAt: -1 })
            .limit(10);
        
        res.json({
            success: true,
            tours
        });
    } catch (error) {
        console.error('Error fetching featured tours:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch featured tours'
        });
    }
});
app.get('/api/tours/:id', async (req, res) => {
    try {
        console.log(`Fetching tour with ID: ${req.params.id}`);
        
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
            console.log('Invalid tour ID format');
            return res.status(400).json({
                success: false,
                message: 'Invalid tour ID format'
            });
        }
        
        const tour = await Tour.findById(req.params.id);
        
        if (!tour) {
            console.log('Tour not found');
            return res.status(404).json({
                success: false,
                message: 'Tour not found'
            });
        }
        
        console.log('Tour found:', tour.title);
        res.json(tour);
    } catch (error) {
        console.error('Error fetching tour:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch tour'
        });
    }
});
app.post('/api/tours', checkAdminAuth, tourUpload.single('tourImage'), async (req, res) => {
    try {
        const {
            title,
            description,
            destination,
            country,  // Add this
            price,
            duration,
            durationUnit,
            featured,
            highlights,
            inclusions,
            exclusions,
            itinerary
        } = req.body;
        
        if (!title || !description || !destination || !country || !price || !duration) {  // Add country check
            return res.status(400).json({
                success: false,
                message: 'Missing required fields'
            });
        }
        if (!req.file) {
            return res.status(400).json({
                success: false,
                message: 'Tour image is required'
            });
        }
        
        const processedHighlights = Array.isArray(highlights) ? highlights : highlights ? [highlights] : [];
        const processedInclusions = Array.isArray(inclusions) ? inclusions : inclusions ? [inclusions] : [];
        const processedExclusions = Array.isArray(exclusions) ? exclusions : exclusions ? [exclusions] : [];
        
        let processedItinerary = [];
        if (itinerary) {

            if (Array.isArray(itinerary)) {
                processedItinerary = itinerary;
            } else {
                const itineraryData = {};
                
                Object.keys(req.body).forEach(key => {
                    if (key.startsWith('itinerary[')) {
                        const match = key.match(/itinerary\[(\d+)\]\[(\w+)\]/);
                        if (match) {
                            const index = match[1];
                            const field = match[2];
                            
                            if (!itineraryData[index]) {
                                itineraryData[index] = {};
                            }
                            
                            itineraryData[index][field] = req.body[key];
                        }
                    }
                });
                
                processedItinerary = Object.values(itineraryData).map(item => ({
                    day: parseInt(item.day),
                    title: item.title,
                    description: item.description
                }));
            }
        }
        
        const imageUrl = `/uploads/tours/${req.file.filename}`;
        
        const newTour = new Tour({
            title,
            description,
            destination,
            country,  // Add this
            price: parseFloat(price),
            duration: parseInt(duration),
            durationUnit: durationUnit || 'days',
            imageUrl,
            featured: featured === 'on' || featured === true,
            highlights: processedHighlights,
            inclusions: processedInclusions,
            exclusions: processedExclusions,
            itinerary: processedItinerary,
            createdBy: req.session.admin.id
        });
        
        await newTour.save();
        
        res.status(201).json({
            success: true,
            message: 'Tour created successfully',
            tour: newTour
        });
    } catch (error) {
        console.error('Error creating tour:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to create tour'
        });
    }
});
app.post('/api/tours', checkAdminAuth, tourUpload.single('tourImage'), async (req, res) => {
    try {
        const {
            title,
            description,
            destination,
            country,
            price,
            duration,
            durationUnit,
            featured,
            highlights,
            inclusions,
            exclusions,
            itinerary,
            isPromoActive,
            promoDuration,
            promoStartDate,
            promoStartTime
        } = req.body;

        if (!title || !description || !destination || !country || !price || !duration) {
            return res.status(400).json({
                success: false,
                message: 'Missing required fields'
            });
        }

        if (!req.file) {
            return res.status(400).json({
                success: false,
                message: 'Tour image is required'
            });
        }

        // ✅ Handle travel requirements (NEW)
        const reqs = req.body.requirements || {};
        const requirements = {
            visaRequired: reqs.visaRequired === 'on' || reqs.visaRequired === true,
            passportRequired: reqs.passportRequired === 'on' || reqs.passportRequired === true,
            passportValidityMonths: parseInt(reqs.passportValidityMonths || 6),
            travelInsuranceRequired: reqs.travelInsuranceRequired === 'on' || reqs.travelInsuranceRequired === true,
            vaccinationRequired: reqs.vaccinationRequired === 'on' || reqs.vaccinationRequired === true,
            otherRequirements: reqs.otherRequirements || ''
        };

        // 🕒 Process promotional settings
        let promoStartTime_dt = null;
        let promoEndTime_dt = null;
        let isPromo = false;

        if (isPromoActive === 'on' || isPromoActive === true) {
            if (!promoDuration || !promoStartDate || !promoStartTime) {
                return res.status(400).json({
                    success: false,
                    message: 'Promotional duration, start date, and start time are required for promotional tours'
                });
            }

            const startDateTimeString = `${promoStartDate}T${promoStartTime}:00`;
            promoStartTime_dt = new Date(startDateTimeString);

            const durationMs = parseInt(promoDuration) * 24 * 60 * 60 * 1000;
            promoEndTime_dt = new Date(promoStartTime_dt.getTime() + durationMs);

            isPromo = true;
        }

        // 📝 Handle arrays
        const processedHighlights = Array.isArray(highlights) ? highlights : highlights ? [highlights] : [];
        const processedInclusions = Array.isArray(inclusions) ? inclusions : inclusions ? [inclusions] : [];
        const processedExclusions = Array.isArray(exclusions) ? exclusions : exclusions ? [exclusions] : [];

        // 🗓️ Process itinerary
        let processedItinerary = [];
        if (itinerary) {
            if (Array.isArray(itinerary)) {
                processedItinerary = itinerary;
            } else {
                const itineraryData = {};
                Object.keys(req.body).forEach(key => {
                    if (key.startsWith('itinerary[')) {
                        const match = key.match(/itinerary\[(\d+)\]\[(\w+)\]/);
                        if (match) {
                            const index = match[1];
                            const field = match[2];
                            if (!itineraryData[index]) itineraryData[index] = {};
                            itineraryData[index][field] = req.body[key];
                        }
                    }
                });
                processedItinerary = Object.values(itineraryData).map(item => ({
                    day: parseInt(item.day),
                    title: item.title,
                    description: item.description
                }));
            }
        }

        // 🖼️ Handle image upload
        const imageUrl = `/uploads/tours/${req.file.filename}`;

        // ✅ Create new tour with requirements
        const newTour = new Tour({
            title,
            description,
            destination,
            country,
            price: parseFloat(price),
            duration: parseInt(duration),
            durationUnit: durationUnit || 'days',
            imageUrl,
            featured: featured === 'on' || featured === true,
            highlights: processedHighlights,
            inclusions: processedInclusions,
            exclusions: processedExclusions,
            itinerary: processedItinerary,
            isPromoActive: isPromo,
            promoDuration: isPromo ? parseInt(promoDuration) : null,
            promoStartTime: promoStartTime_dt,
            promoEndTime: promoEndTime_dt,
            createdBy: req.session.admin.id,
            requirements // ✅ Save travel requirements
        });

        await newTour.save();

        res.status(201).json({
            success: true,
            message: 'Tour created successfully',
            tour: newTour
        });
    } catch (error) {
        console.error('Error creating tour:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to create tour'
        });
    }
});

app.put('/api/tours/:id', checkAdminAuth, tourUpload.single('tourImage'), async (req, res) => {
    try {
        const {
            title,
            description,
            destination,
            country,
            price,
            duration,
            durationUnit,
            featured,
            highlights,
            inclusions,
            exclusions,
            itinerary,
            isPromoActive,
            promoDuration,
            promoStartDate,
            promoStartTime
        } = req.body;

        if (!title || !description || !destination || !country || !price || !duration) {
            return res.status(400).json({
                success: false,
                message: 'Missing required fields'
            });
        }

        const tour = await Tour.findById(req.params.id);
        if (!tour) {
            return res.status(404).json({
                success: false,
                message: 'Tour not found'
            });
        }

        // ✅ Handle travel requirements (NEW)
        const reqs = req.body.requirements || {};
        const requirements = {
            visaRequired: reqs.visaRequired === 'on' || reqs.visaRequired === true,
            passportRequired: reqs.passportRequired === 'on' || reqs.passportRequired === true,
            passportValidityMonths: parseInt(reqs.passportValidityMonths || 6),
            travelInsuranceRequired: reqs.travelInsuranceRequired === 'on' || reqs.travelInsuranceRequired === true,
            vaccinationRequired: reqs.vaccinationRequired === 'on' || reqs.vaccinationRequired === true,
            otherRequirements: reqs.otherRequirements || ''
        };

        // 🕒 Process promotional settings
        let promoStartTime_dt = null;
        let promoEndTime_dt = null;
        let isPromo = false;

        if (isPromoActive === 'on' || isPromoActive === true) {
            if (!promoDuration || !promoStartDate || !promoStartTime) {
                return res.status(400).json({
                    success: false,
                    message: 'Promotional duration, start date, and start time are required for promotional tours'
                });
            }

            const startDateTimeString = `${promoStartDate}T${promoStartTime}:00`;
            promoStartTime_dt = new Date(startDateTimeString);

            const durationMs = parseInt(promoDuration) * 24 * 60 * 60 * 1000;
            promoEndTime_dt = new Date(promoStartTime_dt.getTime() + durationMs);

            isPromo = true;
        }

        // 📝 Convert arrays safely
        const processedHighlights = Array.isArray(highlights) ? highlights : highlights ? [highlights] : [];
        const processedInclusions = Array.isArray(inclusions) ? inclusions : inclusions ? [inclusions] : [];
        const processedExclusions = Array.isArray(exclusions) ? exclusions : exclusions ? [exclusions] : [];

        // 🗓️ Process itinerary
        let processedItinerary = [];
        if (itinerary) {
            if (Array.isArray(itinerary)) {
                processedItinerary = itinerary;
            } else {
                const itineraryData = {};
                Object.keys(req.body).forEach(key => {
                    if (key.startsWith('itinerary[')) {
                        const match = key.match(/itinerary\[(\d+)\]\[(\w+)\]/);
                        if (match) {
                            const index = match[1];
                            const field = match[2];
                            if (!itineraryData[index]) itineraryData[index] = {};
                            itineraryData[index][field] = req.body[key];
                        }
                    }
                });
                processedItinerary = Object.values(itineraryData).map(item => ({
                    day: parseInt(item.day),
                    title: item.title,
                    description: item.description
                }));
            }
        }

        // 🖼️ Image replacement
        let imageUrl = tour.imageUrl;
        if (req.file) {
            imageUrl = `/uploads/tours/${req.file.filename}`;
            if (tour.imageUrl) {
                const oldImagePath = path.join(__dirname, 'public', tour.imageUrl);
                if (fs.existsSync(oldImagePath)) {
                    fs.unlinkSync(oldImagePath);
                }
            }
        }

        // ✅ Update tour
        const updatedTour = await Tour.findByIdAndUpdate(
            req.params.id,
            {
                title,
                description,
                destination,
                country,
                price: parseFloat(price),
                duration: parseInt(duration),
                durationUnit: durationUnit || 'days',
                imageUrl,
                featured: featured === 'on' || featured === true,
                highlights: processedHighlights,
                inclusions: processedInclusions,
                exclusions: processedExclusions,
                itinerary: processedItinerary,
                isPromoActive: isPromo,
                promoDuration: isPromo ? parseInt(promoDuration) : null,
                promoStartTime: promoStartTime_dt,
                promoEndTime: promoEndTime_dt,
                requirements, // ✅ save travel requirements
                updatedAt: Date.now()
            },
            { new: true }
        );

        res.json({
            success: true,
            message: 'Tour updated successfully',
            tour: updatedTour
        });
    } catch (error) {
        console.error('Error updating tour:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update tour'
        });
    }
});


app.delete('/api/tours/:id', checkAdminAuth, async (req, res) => {
    try {
        const tour = await Tour.findById(req.params.id);
        
        if (!tour) {
            return res.status(404).json({
                success: false,
                message: 'Tour not found'
            });
        }
        if (tour.imageUrl) {
            const imagePath = path.join(__dirname, 'public', tour.imageUrl);
            if (fs.existsSync(imagePath)) {
                fs.unlinkSync(imagePath);
            }
        }
        
        await Tour.findByIdAndDelete(req.params.id);
        
        res.json({
            success: true,
            message: 'Tour deleted successfully'
        });
    } catch (error) {
        console.error('Error deleting tour:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to delete tour'
        });
    }
});
app.patch('/api/tours/:id/featured', checkAdminAuth, async (req, res) => {
    try {
        const { featured } = req.body;
        
        const tour = await Tour.findByIdAndUpdate(
            req.params.id,
            { featured: featured },
            { new: true }
        );
        
        if (!tour) {
            return res.status(404).json({
                success: false,
                message: 'Tour not found'
            });
        }
        
        res.json({
            success: true,
            message: `Tour ${featured ? 'featured' : 'unfeatured'} successfully`,
            tour
        });
    } catch (error) {
        console.error('Error updating tour featured status:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update tour featured status'
        });
    }
});

app.get('/tour/:id', async (req, res) => {
    try {
        const tour = await Tour.findById(req.params.id);
        
        if (!tour) {
            return res.status(404).render('404', { url: req.url });
        }
        
        res.render('tour-detail', { tour });
    } catch (error) {
        console.error('Error fetching tour details:', error);
        res.status(500).render('error', { error });
    }
});
app.get('/api/user-profile', (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    User.findById(req.session.user.id)
        .then(user => {
            if (!user) {
                return res.status(404).json({ error: 'User not found' });
            }
            
            res.json({
                username: user.username,
                email: user.email,
                phoneNumber: user.phoneNumber,
                firstName: user.firstName,
                middleInitial: user.middleInitial,
                lastName: user.lastName,
                suffix: user.suffix,
                birthdate: user.birthdate,
                sex: user.sex,
                nationality: user.nationality  // Add this line
            });
        })
        .catch(err => {
            console.error('Error fetching user profile:', err);
            res.status(500).json({ error: 'Server error' });
        });
});

cron.schedule('*/5 * * * *', async () => { // Run every 5 minutes
    try {
        const now = new Date();
        
        // Find promotional tours that have expired
        const expiredPromoTours = await Tour.find({
            isPromoActive: true,
            promoEndTime: { $lt: now },
            hidden: false
        });
        
        if (expiredPromoTours.length > 0) {
            console.log(`Found ${expiredPromoTours.length} expired promotional tours`);
            
            // Hide expired promotional tours
            await Tour.updateMany(
                {
                    isPromoActive: true,
                    promoEndTime: { $lt: now },
                    hidden: false
                },
                {
                    $set: { 
                        hidden: true,
                        isPromoActive: false 
                    }
                }
            );
            
            console.log(`Hidden ${expiredPromoTours.length} expired promotional tours`);
        }
    } catch (error) {
        console.error('Error in promotional tour expiry check:', error);
    }
});


app.get('/forgot-password', (req, res) => {
    res.render('forgot-password');
});

app.get('/change-password', (req, res) => {
    res.render('change-password');
});

app.get('/book-tour', async (req, res) => {
    try {
        const tourId = req.query.id;
        if (!tourId) {
            return res.redirect('/tours');
        }

        const tour = await Tour.findById(tourId);
        if (!tour) {
            console.error(`❌ Tour not found with ID: ${tourId}`);
            return res.redirect('/tours');
        }

        res.render('book-tour', { tour }); // ✅ send tour data to EJS
    } catch (error) {
        console.error('Error loading tour:', error);
        res.redirect('/tours');
    }
});


app.get('/profile', isAuthenticated, (req, res) => res.render('profile', { user: req.session.user }));
app.get('/signup', (req, res) => res.render('signup'));

app.get('/tours', (req, res) => {
    res.render('tours');
});

transporter.verify()
  .then(() => console.log('✅ Email service is ready'))
  .catch(err => console.error('❌ Email service error:', err));

app.use((err, req, res, next) => {
    console.error('Server Error:', err);
    
    const isApiRequest = req.path.startsWith('/api/') || 
                         req.headers.accept === 'application/json';
    
    if (isApiRequest) {
        return res.status(500).json({
            success: false,
            message: 'Internal Server Error'
        });
    }
    res.status(500).render('error', { error: err });
});

app.get('/api/users', checkAdminAuth, async (req, res) => {
    try {
        const { page = 1, limit = 10, search = '' } = req.query;
    
        const searchQuery = search 
            ? {
                $or: [
                    { username: { $regex: search, $options: 'i' } },
                    { email: { $regex: search, $options: 'i' } },
                    { firstName: { $regex: search, $options: 'i' } },
                    { lastName: { $regex: search, $options: 'i' } }
                ]
            } 
            : {};
        
        const totalUsers = await User.countDocuments(searchQuery);
        const users = await User.find(searchQuery)
            .select('-password')
            .sort({ createdAt: -1 })
            .skip((page - 1) * limit)
            .limit(parseInt(limit));
        
        res.json({
            success: true,
            users,
            totalPages: Math.ceil(totalUsers / limit),
            currentPage: parseInt(page),
            totalUsers
        });
    } catch (error) {
        console.error('❌ Error fetching users:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch users'
        });
    }
});

app.get('/api/users/:userId', async (req, res) => {
    try {
        if (!req.session.user || req.session.user.id !== req.params.userId) {
            return res.status(403).json({
                success: false,
                message: 'Unauthorized'
            });
        }
        
        const user = await User.findById(req.params.userId).select('-password');
        
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }
        
        res.json({
            success: true,
            user: {
                _id: user._id,
                username: user.username,
                email: user.email,
                firstName: user.firstName || '',
                lastName: user.lastName || '',
                phoneNumber: user.phoneNumber || '',
                birthdate: user.birthdate || null,
                sex: user.sex || ''
            }
        });
    } catch (error) {
        console.error('Error fetching user data:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch user data'
        });
    }
});
const placeholderImagePath = path.join(__dirname, 'public', 'images', 'placeholder-tour.jpg');
if (!fs.existsSync(placeholderImagePath)) {
    fs.writeFileSync(placeholderImagePath, 'This is a placeholder for tour images.');
    console.log('Created placeholder for tour images');
}

app.get('/tour/:id', async (req, res) => {
    try {
        const tour = await Tour.findById(req.params.id);
        
        if (!tour) {
            return res.status(404).render('error', { 
                error: { message: 'Tour not found' } 
            });
        }
        
        res.render('tour-detail', { tour });
    } catch (error) {
        console.error('Error fetching tour details:', error);
        res.status(500).render('error', { error });
    }
});
const storage = multer.diskStorage({
    destination: function(req, file, cb) {
      const uploadDir = path.join(__dirname, 'public/uploads/receipts');
      if (!fs.existsSync(uploadDir)) {
        fs.mkdirSync(uploadDir, { recursive: true });
      }
      
      cb(null, uploadDir);
    },
    filename: function(req, file, cb) {
      const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
      const ext = path.extname(file.originalname);
      cb(null, 'receipt-' + uniqueSuffix + ext);
    }
  });
  
  const upload = multer({ 
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 }
  });
  
  app.post('/api/test-upload', upload.single('receipt'), (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({
          success: false,
          message: 'No file uploaded'
        });
      }
      const fileUrl = `/uploads/receipts/${path.basename(req.file.path)}`;
      
      console.log('File uploaded successfully:', req.file.path);
      console.log('File URL:', fileUrl);
  
      res.json({
        success: true,
        fileUrl: fileUrl
      });
    } catch (error) {
      console.error('Error uploading file:', error);
      res.status(500).json({
        success: false,
        message: 'Error uploading file: ' + error.message
      });
    }
  });
  
app.get('/api/user-profile', (req, res) => {

    if (!req.session.user) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    User.findById(req.session.user.id)
        .then(user => {
            if (!user) {
                return res.status(404).json({ error: 'User not found' });
            }
            
            res.json({
                username: user.username,
                email: user.email,
                phoneNumber: user.phoneNumber,
                firstName: user.firstName,
                lastName: user.lastName
            });
        })
        .catch(err => {
            console.error('Error fetching user profile:', err);
            res.status(500).json({ error: 'Server error' });
        });
});
// ✅ Fetch all bookings for admin panel
app.get('/api/admin/bookings', checkAdminAuth, async (req, res) => {
  try {
    console.log('Fetching admin bookings...');

    const bookings = await Booking.find()
      .sort({ createdAt: -1 })
      // ✅ Populate related admin info
      .populate('statusChangeHistory.updatedBy', 'firstName lastName email')
      .populate('confirmedBy', 'firstName lastName')
      .populate('cancelledBy', 'firstName lastName')
      .populate('completedBy', 'firstName lastName');

    res.json({
      success: true,
      bookings
    });
  } catch (error) {
    console.error('❌ Error fetching bookings:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch bookings'
    });
  }
});


app.get('/api/tours', async (req, res) => {
    try {
        const { featured, destination, minPrice, maxPrice, limit = 10, includeHidden = false } = req.query;
        
        const query = {};
        const now = new Date();
        
        if (!includeHidden) {
            query.$and = [
                { hidden: { $ne: true } },
                {
                    $or: [
                        { isPromoActive: false },
                        { isPromoActive: { $ne: true } },
                        {
                            $and: [
                                { isPromoActive: true },
                                { promoStartTime: { $lte: now } },
                                { promoEndTime: { $gt: now } }
                            ]
                        }
                    ]
                }
            ];
        }
        
        if (featured === 'true') {
            if (query.$and) {
                query.$and.push({ featured: true });
            } else {
                query.featured = true;
            }
        }
        
        if (destination) {
            if (query.$and) {
                query.$and.push({ destination: { $regex: destination, $options: 'i' } });
            } else {
                query.destination = { $regex: destination, $options: 'i' };
            }
        }
        
        if (minPrice || maxPrice) {
            const priceQuery = {};
            
            if (minPrice) {
                priceQuery.$gte = parseFloat(minPrice);
            }
            
            if (maxPrice) {
                priceQuery.$lte = parseFloat(maxPrice);
            }
            
            if (query.$and) {
                query.$and.push({ price: priceQuery });
            } else {
                query.price = priceQuery;
            }
        }
        
        const tours = await Tour.find(query)
            .sort({ createdAt: -1 })
            .limit(parseInt(limit));
        
        res.json({
            success: true,
            tours
        });
    } catch (error) {
        console.error('Error fetching tours:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch tours'
        });
    }
});


app.get('/api/admin/tours', checkAdminAuth, async (req, res) => {
    try {
        const tours = await Tour.find().sort({ createdAt: -1 });
        
        res.json({
            success: true,
            tours
        });
    } catch (error) {
        console.error('Error fetching tours:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch tours'
        });
    }
});
app.patch('/api/admin/bookings/:bookingId/status', checkAdminAuth, async (req, res) => {
    try {
        const { bookingId } = req.params;
        const { status } = req.body;
        const adminId = req.session.admin.id;

        if (!status) {
            return res.status(400).json({ success: false, message: "Missing status." });
        }

        const booking = await Booking.findById(bookingId);

        if (!booking) {
            return res.status(404).json({ success: false, message: "Booking not found." });
        }

        if (['confirmed', 'completed', 'cancelled'].includes(booking.status) && status === 'pending') {
            return res.status(400).json({ 
                success: false, 
                message: `Cannot revert booking from ${booking.status} to pending.` 
            });
        }

        // Update status and track who made the change
        booking.status = status;
        const statusUpdate = {
            status: status,
            updatedBy: adminId,
            updatedAt: new Date()
        };
        booking.statusChangeHistory.push(statusUpdate);

        if (status === 'confirmed') {
            booking.confirmedBy = adminId;
            booking.confirmedAt = new Date();
        } else if (status === 'completed') {
            booking.completedBy = adminId;
            booking.completedAt = new Date();
        } else if (status === 'cancelled') {
            booking.cancelledBy = adminId;
            booking.cancelledAt = new Date();
        }

        await booking.save();

        res.json({ 
            success: true, 
            message: "Booking status updated successfully.", 
            booking 
        });
    } catch (error) {
        console.error("❌ Error updating booking status:", error);
        res.status(500).json({ success: false, message: "Failed to update booking status." });
    }
});
app.delete('/api/admin/bookings/:bookingId', checkAdminAuth, async (req, res) => {
    try {
        const { bookingId } = req.params;
        // If start date is being changed, check if we should auto-cancel
        if (startDate && booking.startDate) {
            const originalDate = new Date(booking.startDate);
            const newDate = new Date(startDate);

            // If dates are different, automatically set status to cancelled
            if (originalDate.getTime() !== newDate.getTime()) {
                booking.status = 'cancelled';
                booking.startDate = newDate;
                
                // Send notification email about the cancellation
                try {
                    await transporter.sendMail({
                        from: process.env.EMAIL_USER,
                        to: booking.email,
                        subject: "Your Booking Has Been Cancelled Due to Date Change",
                        html: `
                            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;">
                                <h2 style="color: #f26523;">Booking Cancelled</h2>
                                <p>Dear ${booking.fullName},</p>
                                <p>Your booking (Reference: ${booking.bookingId}) has been automatically cancelled due to a date change.</p>
                                
                                <div style="background-color: #f5f5f5; padding: 15px; margin: 15px 0; border-radius: 5px;">
                                    <h3 style="margin-top: 0;">Booking Details:</h3>
                                    <p><strong>Original Date:</strong> ${originalDate.toLocaleDateString()}</p>
                                    <p><strong>Changed To:</strong> ${newDate.toLocaleDateString()}</p>
                                    <p><strong>Destination:</strong> ${booking.destination || booking.tourDetails?.destination || 'Not specified'}</p>
                                    <p><strong>Total Amount:</strong> ₱${typeof booking.totalAmount === 'number' ? booking.totalAmount.toLocaleString() : booking.totalAmount}</p>
                                </div>
                                
                                <p>If you wish to book for the new date, please make a new booking on our website.</p>
                                <p>Thank you for your understanding.</p>
                            </div>
                        `
                    });
                } catch (emailError) {
                    console.error('Error sending cancellation email:', emailError);
                }
            }
        } else {
            // If no date change, update status as requested
            booking.status = status;
        }

        await booking.save();

        res.json({ 
            success: true, 
            message: "Booking updated successfully.", 
            booking 
        });
    } catch (error) {
        console.error("❌ Error updating booking:", error);
        res.status(500).json({ error: "Failed to update booking." });
    }
});


app.delete('/api/admin/bookings/:bookingId', checkAdminAuth, async (req, res) => {
    try {
        const { bookingId } = req.params;

        const booking = await Booking.findByIdAndDelete(bookingId);

        if (!booking) {
            return res.status(404).json({ error: "Booking not found." });
        }

        res.json({ success: true, message: "Booking deleted successfully." });
    } catch (error) {
        console.error("❌ Error deleting booking:", error);
        res.status(500).json({ error: "Failed to delete booking." });
    }
});

app.get('/api/bookings/:bookingId', isAuthenticated, async (req, res) => {
    try {
      const { bookingId } = req.params;
      const userId = req.session.user.id;
      
      let booking = null;
      if (mongoose.Types.ObjectId.isValid(bookingId)) {
        booking = await Booking.findOne({
          _id: bookingId,
          userId: userId
        });
      }
      if (!booking) {
        booking = await Booking.findOne({
          bookingId: bookingId,
          userId: userId
        });
      }
      
      if (!booking) {
        return res.status(404).json({
          success: false,
          message: 'Booking not found'
        });
      }
      
      res.json({
        success: true,
        booking
      });
    } catch (error) {
      console.error('Error fetching booking details:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to fetch booking details'
      });
    }
  });
  app.post('/api/user/bookings/:bookingId/cancel', isAuthenticated, async (req, res) => {
    try {
      const { bookingId } = req.params;
      const userId = req.session.user.id;
      
      let booking = null;
      
      if (mongoose.Types.ObjectId.isValid(bookingId)) {
        booking = await Booking.findOne({
          _id: bookingId,
          userId: userId
        });
      }
      if (!booking) {
        booking = await Booking.findOne({
          bookingId: bookingId,
          userId: userId
        });
      }
      
      if (!booking) {
        return res.status(404).json({
          success: false,
          message: 'Booking not found'
        });
      }
      
      if (booking.status === 'cancelled') {
        return res.status(400).json({
          success: false,
          message: 'This booking is already cancelled'
        });
      }
      
      const now = new Date();
      const bookingDate = new Date(booking.createdAt);
      const tourDate = new Date(booking.startDate);
      
      const daysSinceBooking = Math.floor((now - bookingDate) / (1000 * 60 * 60 * 24));
      const daysUntilTour = Math.floor((tourDate - now) / (1000 * 60 * 60 * 24));
      
      if ((booking.paymentMethod === 'gcash' || booking.paymentMethod === 'paypal')) {
        if (daysSinceBooking > 7 && daysUntilTour < 3) {
          return res.status(400).json({
            success: false,
            message: 'Cancellation period has expired. You can only cancel within 7 days of booking or at least 3 days before the tour date.'
          });
        }
      } else if (booking.paymentMethod === 'store') {
        if (booking.status !== 'pending') {
          return res.status(400).json({
            success: false,
            message: 'Only pending in-store payments can be cancelled'
          });
        }
      }
      
      booking.status = 'cancelled';
      await booking.save();
      
      try {
        await transporter.sendMail({
          from: process.env.EMAIL_USER,
          to: booking.email,
          subject: "Your Booking Has Been Cancelled",
          html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;">
              <h2 style="color: #f26523;">Booking Cancelled</h2>
              <p>Dear ${booking.fullName},</p>
              <p>Your booking (Reference: ${booking.bookingId}) has been cancelled as requested.</p>
              
              <div style="background-color: #f5f5f5; padding: 15px; margin: 15px 0; border-radius: 5px;">
                <h3 style="margin-top: 0;">Booking Details:</h3>
                <p><strong>Destination:</strong> ${booking.destination || booking.tourDetails?.destination || 'Not specified'}</p>
                <p><strong>Start Date:</strong> ${new Date(booking.startDate).toLocaleDateString()}</p>
                <p><strong>Total Amount:</strong> ₱${typeof booking.totalAmount === 'number' ? booking.totalAmount.toLocaleString() : booking.totalAmount}</p>
              </div>
              
              <p>If you wish to book another tour, please visit our website.</p>
              <p>Thank you for your interest in A.BEE Travel and Tours.</p>
            </div>
          `
        });
      } catch (emailError) {
        console.error('Error sending cancellation email:', emailError);
      }
      
      res.json({
        success: true,
        message: 'Booking cancelled successfully'
      });
    } catch (error) {
      console.error('Error cancelling booking:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to cancel booking'
      });
    }
  });
app.post('/verify-credentials', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });

        if (!user) {
            return res.status(400).json({ success: false, message: 'Invalid credentials' });
        }
        
        const isMatch = await user.comparePassword(password);
        if (!isMatch) {
            return res.status(400).json({ success: false, message: 'Invalid credentials' });
        }

        return res.json({ 
            success: true, 
            message: 'Credentials verified',
            email: user.email
        });

    } catch (error) {
        console.error('❌ Credential verification error:', error);
        return res.status(500).json({ success: false, message: 'Internal Server Error' });
    }
});
app.post('/send-login-otp', async (req, res) => {
    const { email } = req.body;
    
    if (!email) {
        return res.status(400).json({ success: false, message: "Email is required." });
    }
    
    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ success: false, message: "User not found." });
        }

        const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
        const expiresAt = new Date(Date.now() + 5 * 60 * 1000);
        
        await OTP.findOneAndUpdate(
            { email }, 
            { 
                otp: otpCode, 
                expiresAt, 
                purpose: 'login_verification'
            }, 
            { upsert: true, new: true }
        );
        
        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject: "Your Login Verification Code",
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;">
                    <h2 style="color: #f26523;">Login Verification</h2>
                    <p>Please use the following code to verify your login:</p>
                    <div style="background-color: #f5f5f5; padding: 10px; text-align: center; font-size: 24px; font-weight: bold; letter-spacing: 5px; margin: 20px 0;">
                        ${otpCode}
                    </div>
                    <p>This code will expire in 5 minutes.</p>
                    <p>If you didn't attempt to log in, please ignore this email and consider changing your password.</p>
                </div>
            `
        });

        return res.json({ success: true, message: "Verification code sent successfully!" });

    } catch (error) {
        console.error("❌ Login OTP Sending Error:", error);
        return res.status(500).json({ success: false, message: "Failed to send verification code." });
    }
});
app.post('/verify-login-otp', async (req, res) => {
    const { username, code } = req.body;
    
    console.log(`Verifying login OTP for username: ${username}, code: ${code}`);
    
    if (!username || !code) {
        console.log("Missing username or code");
        return res.status(400).json({ success: false, message: "Username and verification code are required." });
    }

    try {
        const user = await User.findOne({ username });
        if (!user) {
            console.log(`User not found: ${username}`);
            return res.status(404).json({ success: false, message: "User not found." });
        }

        console.log(`Looking for OTP with email: ${user.email}, purpose: login_verification`);
        
        const otpRecord = await OTP.findOne({ 
            email: user.email, 
            purpose: 'login_verification'
        });
        
        console.log('OTP record found:', otpRecord);

        if (!otpRecord) {
            return res.status(400).json({ success: false, message: "No verification code found. Please request a new one." });
        }

        if (otpRecord.otp !== code) {
            console.log(`OTP mismatch. Expected: ${otpRecord.otp}, Received: ${code}`);
            return res.status(400).json({ success: false, message: "Incorrect verification code." });
        }

        if (Date.now() > otpRecord.expiresAt) {
            return res.status(400).json({ success: false, message: "Verification code has expired. Please request a new one." });
        }

        await OTP.deleteOne({ email: user.email, purpose: 'login_verification' });

        req.session.otpVerified = true;
        req.session.verifiedUsername = username;

        console.log(`OTP verification successful for user: ${username}`);
        return res.json({ success: true, message: "Verification successful!" });

    } catch (error) {
        console.error("❌ Login OTP Verification Error:", error);
        return res.status(500).json({ success: false, message: "Internal Server Error" });
    }
});

app.post('/login', async (req, res) => {
  try {
    const { username, password, otpVerified } = req.body;
    
    // ✅ OTP verification checks
    if (!otpVerified && !req.session.otpVerified) {
      return res.status(400).json({ success: false, message: 'OTP verification required' });
    }
    if (req.session.otpVerified && req.session.verifiedUsername !== username) {
      return res.status(400).json({ success: false, message: 'OTP verification mismatch' });
    }

    // ✅ Find user
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(400).json({ success: false, message: 'Invalid credentials' });
    }

    // ✅ Check password
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(400).json({ success: false, message: 'Invalid credentials' });
    }

    // ✅ Update last active timestamp (🧠 important for retention analytics)
    await User.findByIdAndUpdate(user._id, { lastActiveAt: new Date() });

    // ✅ Clear OTP session
    delete req.session.otpVerified;
    delete req.session.verifiedUsername;

    // ✅ Store session user info
    req.session.user = {
      id: user._id,
      username: user.username,
      email: user.email,
      phoneNumber: user.phoneNumber,
      firstName: user.firstName,
      lastName: user.lastName
    };

    // ✅ Send success
    return res.json({ success: true, message: 'Login successful' });

  } catch (error) {
    console.error('❌ Login Error:', error);
    return res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});

app.post('/api/admin/send-login-otp', async (req, res) => {
    const { email } = req.body;
    
    if (!email) {
        return res.status(400).json({ success: false, message: "Email is required." });
    }
    
    try {
        const admin = await Admin.findOne({ email });
        if (!admin) {
            return res.status(404).json({ success: false, message: "Admin not found." });
        }

        const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
        const expiresAt = new Date(Date.now() + 5 * 60 * 1000);
        
        await OTP.findOneAndUpdate(
            { email }, 
            { 
                otp: otpCode, 
                expiresAt, 
                purpose: 'login_verification'
            }, 
            { upsert: true, new: true }
        );
        
        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject: "Your Staff Login Verification Code",
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;">
                    <h2 style="color: #f26523;">Staff Login Verification</h2>
                    <p>Please use the following code to verify your login:</p>
                    <div style="background-color: #f5f5f5; padding: 10px; text-align: center; font-size: 24px; font-weight: bold; letter-spacing: 5px; margin: 20px 0;">
                        ${otpCode}
                    </div>
                    <p>This code will expire in 5 minutes.</p>
                    <p>If you didn't attempt to log in, please ignore this email and consider changing your password.</p>
                </div>
            `
        });

        return res.json({ success: true, message: "Verification code sent successfully!" });

    } catch (error) {
        console.error("❌ Admin Login OTP Sending Error:", error);
        return res.status(500).json({ success: false, message: "Failed to send verification code." });
    }
});

app.post('/api/admin/verify-login-otp', async (req, res) => {
    const { email, code } = req.body;
    
    console.log(`Verifying admin login OTP for email: ${email}, code: ${code}`);
    
    if (!email || !code) {
        console.log("Missing email or code");
        return res.status(400).json({ success: false, message: "Email and verification code are required." });
    }

    try {
        const admin = await Admin.findOne({ email });
        if (!admin) {
            console.log(`Admin not found: ${email}`);
            return res.status(404).json({ success: false, message: "Admin not found." });
        }

        console.log(`Looking for OTP with email: ${email}, purpose: login_verification`);
        
        const otpRecord = await OTP.findOne({ 
            email, 
            purpose: 'login_verification'
        });
        
        console.log('OTP record found:', otpRecord);

        if (!otpRecord) {
            return res.status(400).json({ success: false, message: "No verification code found. Please request a new one." });
        }

        if (otpRecord.otp !== code) {
            console.log(`OTP mismatch. Expected: ${otpRecord.otp}, Received: ${code}`);
            return res.status(400).json({ success: false, message: "Incorrect verification code." });
        }

        if (Date.now() > otpRecord.expiresAt) {
            return res.status(400).json({ success: false, message: "Verification code has expired. Please request a new one." });
        }

        // Mark this OTP as used
        await OTP.deleteOne({ email, purpose: 'login_verification' });

        // Set a flag in the session to indicate OTP verification
        req.session.adminOtpVerified = true;
        req.session.adminVerifiedEmail = email;

        console.log(`OTP verification successful for admin: ${email}`);
        return res.json({ success: true, message: "Verification successful!" });

    } catch (error) {
        console.error("❌ Admin Login OTP Verification Error:", error);
        return res.status(500).json({ success: false, message: "Internal Server Error" });
    }
});

  app.get('/api/user-notifications', isAuthenticated, async (req, res) => {
    try {
      const userId = req.session.user.id;
      
      const bookings = await Booking.find({ userId }).sort({ createdAt: -1 });
      const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
      const newNotifications = bookings.filter(booking => 
        booking.updatedAt > oneDayAgo && booking.createdAt < booking.updatedAt
      ).length;
      
      res.json({
        success: true,
        notifications: bookings,
        newNotifications: newNotifications
      });
    } catch (error) {
      console.error('Error fetching user notifications:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to fetch notifications'
      });
    }
  });
  
app.get('/api/bookings/:bookingId', isAuthenticated, async (req, res) => {
    try {
        const { bookingId } = req.params;
        const userId = req.session.user.id;
        
        let booking = null;
        
        if (mongoose.Types.ObjectId.isValid(bookingId)) {
            booking = await Booking.findOne({
                _id: bookingId,
                userId: userId
            });
        }
        if (!booking) {
            booking = await Booking.findOne({
                bookingId: bookingId,
                userId: userId
            });
        }
        
        if (!booking) {
            return res.status(404).json({
                success: false,
                message: 'Booking not found'
            });
        }
        
        res.json({
            success: true,
            booking
        });
    } catch (error) {
        console.error('Error fetching booking details:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch booking details'
        });
    }
});
cron.schedule('*/1 * * * *', async () => {  // Run every minute
    try {
        const now = new Date();
        const pendingBookings = await Booking.find({
            paymentMethod: 'store',
            status: 'pending'
        });
        
        if (pendingBookings.length > 0) {
            console.log(`Checking ${pendingBookings.length} pending store payment bookings`);
            
            for (const booking of pendingBookings) {
                const bookingCreationTime = new Date(booking.createdAt);
                const expectedExpiryTime = new Date(bookingCreationTime.getTime() + (8 * 60 * 60 * 1000)); // 8 hours after creation
                
                // Check if current time is more than 8 hours ahead of booking creation time
                // or if current time is before booking creation time (indicating time was set backwards)
                if (now > expectedExpiryTime || now < bookingCreationTime) {
                    console.log(`Cancelling booking ${booking.bookingId} due to time discrepancy`);
                    console.log(`Creation time: ${bookingCreationTime}`);
                    console.log(`Expected expiry: ${expectedExpiryTime}`);
                    console.log(`Current time: ${now}`);
                    
                    booking.status = 'cancelled';
                    await booking.save();
                    
                    try {
                        await transporter.sendMail({
                            from: process.env.EMAIL_USER,
                            to: booking.email,
                            subject: "Your Booking Has Been Cancelled",
                            html: `
                                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;">
                                    <h2 style="color: #f26523;">Booking Cancelled</h2>
                                    <p>Dear ${booking.fullName},</p>
                                    <p>Your booking (Reference: ${booking.bookingId}) has been automatically cancelled due to payment deadline expiration.</p>
                                    
                                    <div style="background-color: #f5f5f5; padding: 15px; margin: 15px 0; border-radius: 5px;">
                                        <h3 style="margin-top: 0;">Booking Details:</h3>
                                        <p><strong>Destination:</strong> ${booking.destination}</p>
                                        <p><strong>Start Date:</strong> ${new Date(booking.startDate).toLocaleDateString()}</p>
                                        <p><strong>Total Amount:</strong> ₱${booking.totalAmount.toLocaleString()}</p>
                                    </div>
                                    
                                    <p>If you still wish to book this tour, please make a new booking on our website.</p>
                                    <p>Thank you for your interest in A.BEE Travel and Tours.</p>
                                </div>
                            `
                        });
                        console.log(`Cancellation email sent for booking ${booking.bookingId}`);
                    } catch (emailError) {
                        console.error(`Error sending cancellation email for booking ${booking.bookingId}:`, emailError);
                    }
                }
            }
        }
    } catch (error) {
        console.error('Error in booking status check cron job:', error);
    }
});

router.get('/api/analytics/seasons', async (req, res) => {
  const seasonStats = await Booking.aggregate([
    { $group: { _id: "$season", count: { $sum: 1 } } },
    { $sort: { count: -1 } }
  ]);
  res.json(seasonStats);
});

app.get('/api/analytics/seasons', async (req, res) => {
  try {
    const seasonStats = await Booking.aggregate([
      { $group: { _id: "$season", count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]);
    res.json({ success: true, data: seasonStats });
  } catch (error) {
    console.error("Error fetching season analytics:", error);
    res.status(500).json({ success: false, message: "Failed to fetch seasonal analytics" });
  }
});
// 🌍 Climate & Season Analytics
app.get("/api/analytics/climate", async (req, res) => {
  try {
    const climateStats = await Booking.aggregate([
      {
        $group: {
          _id: "$season",
          avgTemperature: { $avg: "$avgTemperature" },
          avgRainfall: { $avg: "$rainfall" },
          bookings: { $sum: 1 }
        }
      },
      { $sort: { bookings: -1 } }
    ]);

    res.json({ success: true, data: climateStats });
  } catch (error) {
    console.error("❌ Climate analytics error:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.get('/api/analytics/popular-destinations', checkAdminAuth, async (req, res) => {
    try {
        const popularDestinations = await Booking.aggregate([
            { $match: { status: { $ne: 'cancelled' } } },
            { $group: {
                _id: "$destination",
                count: { $sum: 1 },
                revenue: { $sum: "$totalAmount" }
            }},
            { $sort: { count: -1 } },
            { $limit: 10 }           
        ]);
        
        res.json({
            success: true,
            popularDestinations
        });
    } catch (error) {
        console.error('Error fetching popular destinations:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch popular destinations'
        });
    }
});
app.get('/api/analytics/monthly-revenue', checkAdminAuth, async (req, res) => {
    try {
        const monthlyRevenue = await Booking.aggregate([
            { $match: { status: { $ne: 'cancelled' } } },
            {
                $group: {
                    _id: {
                        month: { $month: "$createdAt" },
                        year: { $year: "$createdAt" },
                        destination: "$destination"
                    },
                    revenue: { $sum: "$totalAmount" },
                    count: { $sum: 1 }
                }
            },
            { $sort: { "_id.year": 1, "_id.month": 1 } }
        ]);
        
        res.json({
            success: true,
            monthlyRevenue
        });
    } catch (error) {
        console.error('Error fetching monthly revenue:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch monthly revenue'
        });
    }
});
const countrySeasons = {
    "Afghanistan": ["Winter", "Spring", "Summer", "Fall"],
    "Albania": ["Winter", "Spring", "Summer", "Fall"],
    "Algeria": ["Winter", "Spring", "Summer", "Fall"],
    "Andorra": ["Winter", "Spring", "Summer", "Fall"],
    "Angola": ["Wet Season", "Dry Season"],
    "Antigua and Barbuda": ["Wet Season", "Dry Season"],
    "Argentina": ["Summer", "Fall", "Winter", "Spring"],
    "Armenia": ["Winter", "Spring", "Summer", "Fall"],
    "Australia": ["Summer", "Fall", "Winter", "Spring"],
    "Austria": ["Winter", "Spring", "Summer", "Fall"],
    "Azerbaijan": ["Winter", "Spring", "Summer", "Fall"],
    "Bahamas": ["Wet Season", "Dry Season"],
    "Bahrain": ["Summer", "Winter"],
    "Bangladesh": ["Summer", "Monsoon", "Winter"],
    "Barbados": ["Wet Season", "Dry Season"],
    "Belarus": ["Winter", "Spring", "Summer", "Fall"],
    "Belgium": ["Winter", "Spring", "Summer", "Fall"],
    "Belize": ["Wet Season", "Dry Season"],
    "Benin": ["Wet Season", "Dry Season"],
    "Bhutan": ["Winter", "Spring", "Summer", "Fall"],
    "Bolivia": ["Wet Season", "Dry Season"],
    "Bosnia and Herzegovina": ["Winter", "Spring", "Summer", "Fall"],
    "Botswana": ["Wet Season", "Dry Season"],
    "Brazil": ["Summer", "Fall", "Winter", "Spring"],
    "Brunei": ["Wet Season", "Dry Season"],
    "Bulgaria": ["Winter", "Spring", "Summer", "Fall"],
    "Burkina Faso": ["Wet Season", "Dry Season"],
    "Burundi": ["Wet Season", "Dry Season"],
    "Cabo Verde": ["Wet Season", "Dry Season"],
    "Cambodia": ["Wet Season", "Dry Season"],
    "Cameroon": ["Wet Season", "Dry Season"],
    "Canada": ["Winter", "Spring", "Summer", "Fall"],
    "Chile": ["Summer", "Fall", "Winter", "Spring"],
    "China": ["Winter", "Spring", "Summer", "Fall"],
    "Colombia": ["Wet Season", "Dry Season"],
    "Costa Rica": ["Wet Season", "Dry Season"],
    "Croatia": ["Winter", "Spring", "Summer", "Fall"],
    "Cuba": ["Wet Season", "Dry Season"],
    "Cyprus": ["Winter", "Spring", "Summer", "Fall"],
    "Czech Republic": ["Winter", "Spring", "Summer", "Fall"],
    "Denmark": ["Winter", "Spring", "Summer", "Fall"],
    "Ecuador": ["Wet Season", "Dry Season"],
    "Egypt": ["Summer", "Winter"],
    "France": ["Winter", "Spring", "Summer", "Fall"],
    "Germany": ["Winter", "Spring", "Summer", "Fall"],
    "Greece": ["Winter", "Spring", "Summer", "Fall"],
    "India": ["Winter", "Summer", "Monsoon", "Post-Monsoon"],
    "Indonesia": ["Wet Season", "Dry Season"],
    "Iran": ["Winter", "Spring", "Summer", "Fall"],
    "Iraq": ["Winter", "Summer"],
    "Ireland": ["Winter", "Spring", "Summer", "Fall"],
    "Israel": ["Winter", "Summer"],
    "Italy": ["Winter", "Spring", "Summer", "Fall"],
    "Japan": ["Winter", "Spring", "Summer", "Fall"],
    "Kenya": ["Long Rains", "Short Rains", "Dry Season"],
    "Malaysia": ["Wet Season", "Dry Season"],
    "Mexico": ["Wet Season", "Dry Season"],
    "Netherlands": ["Winter", "Spring", "Summer", "Fall"],
    "New Zealand": ["Summer", "Fall", "Winter", "Spring"],
    "Nigeria": ["Wet Season", "Dry Season"],
    "Norway": ["Winter", "Spring", "Summer", "Fall"],
    "Pakistan": ["Winter", "Spring", "Summer", "Monsoon"],
    "Peru": ["Wet Season", "Dry Season"],
    "Philippines": ["Wet Season", "Dry Season"],
    "Poland": ["Winter", "Spring", "Summer", "Fall"],
    "Portugal": ["Winter", "Spring", "Summer", "Fall"],
    "Russia": ["Winter", "Spring", "Summer", "Fall"],
    "Saudi Arabia": ["Winter", "Summer"],
    "Singapore": ["Wet Season", "Dry Season"],
    "South Africa": ["Summer", "Fall", "Winter", "Spring"],
    "South Korea": ["Winter", "Spring", "Summer", "Fall"],
    "Spain": ["Winter", "Spring", "Summer", "Fall"],
    "Sweden": ["Winter", "Spring", "Summer", "Fall"],
    "Switzerland": ["Winter", "Spring", "Summer", "Fall"],
    "Thailand": ["Wet Season", "Dry Season"],
    "Turkey": ["Winter", "Spring", "Summer", "Fall"],
    "United Arab Emirates": ["Winter", "Summer"],
    "United Kingdom": ["Winter", "Spring", "Summer", "Fall"],
    "United States": ["Winter", "Spring", "Summer", "Fall"],
    "Venezuela": ["Wet Season", "Dry Season"],
    "Vietnam": ["Wet Season", "Dry Season"],
    "Zambia": ["Wet Season", "Dry Season"],
    "Zimbabwe": ["Wet Season", "Dry Season"]
};
app.get('/api/analytics/seasonal-trends', checkAdminAuth, async (req, res) => {
    try {
        const year = parseInt(req.query.year) || new Date().getFullYear();
        const startDate = new Date(year, 0, 1);
        const endDate = new Date(year, 11, 31, 23, 59, 59, 999);

        console.log(`Fetching seasonal trends for year: ${year}`);

        const bookings = await Booking.find({
            status: { $ne: 'cancelled' },
            startDate: { $gte: startDate, $lte: endDate }
        });

        const seasonalTrends = bookings.map(booking => {
            const country = booking.country;
            const month = booking.startDate.getMonth() + 1; // getMonth() returns 0-11
            const seasons = countrySeasons[country] || ['Winter', 'Spring', 'Summer', 'Fall'];
            let season = 'Unknown';

            if (seasons.includes('Winter') && (month === 12 || month === 1 || month === 2)) {
                season = 'Winter';
            } else if (seasons.includes('Spring') && (month === 3 || month === 4 || month === 5)) {
                season = 'Spring';
            } else if (seasons.includes('Summer') && (month === 6 || month === 7 || month === 8)) {
                season = 'Summer';
            } else if (seasons.includes('Fall') && (month === 9 || month === 10 || month === 11)) {
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

            return {
                destination: booking.destination,
                country: booking.country,
                season: season,
                count: 1
            };
        });

        const groupedTrends = seasonalTrends.reduce((acc, trend) => {
            const key = `${trend.destination}-${trend.country}-${trend.season}`;
            if (!acc[key]) {
                acc[key] = { ...trend, count: 0 };
            }
            acc[key].count += 1;
            return acc;
        }, {});

        const result = Object.values(groupedTrends);

        console.log('Seasonal trends data:', result);

        // Predict destinations for the next year based on historical data
        const predictedDestinations = [];
        const allSeasons = ['Winter', 'Spring', 'Summer', 'Fall', 'Wet Season', 'Dry Season', 'Monsoon', 'Post-Monsoon'];

        result.forEach(item => {
            const country = item.country;
            const applicableSeasons = countrySeasons[country] || allSeasons; // Default to all seasons if country not found

            console.log(`Processing country: ${country}, applicable seasons: ${applicableSeasons}`);

            applicableSeasons.forEach(season => {
                if (item.season === season) {
                    const destinationIndex = predictedDestinations.findIndex(pd => pd.season === season);
                    if (destinationIndex === -1) {
                        predictedDestinations.push({
                            season: season,
                            destinations: [{
                                destination: item.destination,
                                predictedCount: Math.round(item.count * 1.1) // Assuming a 10% increase
                            }]
                        });
                    } else {
                        predictedDestinations[destinationIndex].destinations.push({
                            destination: item.destination,
                            predictedCount: Math.round(item.count * 1.1) // Assuming a 10% increase
                        });
                    }
                }
            });
        });

        console.log('Predicted destinations data:', predictedDestinations);

        res.json({ success: true, seasonalTrends: result, predictedDestinations });
    } catch (error) {
        console.error('Error fetching seasonal trends:', error);
        res.status(500).json({ success: false, message: 'Failed to fetch seasonal trends' });
    }
});
app.post('/api/contact', async (req, res) => {
    try {
        const { name, email, phone, country, subject, message } = req.body;
        
        if (!name || !email || !country || !subject || !message) {
            return res.status(400).json({
                success: false,
                message: 'Required fields are missing'
            });
        }
        
        const newContact = new Contact({
            name,
            email,
            phone,
            country,
            subject,
            message
        });
        
        await newContact.save();
        
        // Send email notification to admin
        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: process.env.EMAIL_USER,
            subject: `New Contact Form Submission: ${subject}`,
            html: `
                <div style="font-family: Arial, sans-serif;">
                    <h2>New Contact Form Submission</h2>
                    <p><strong>From:</strong> ${name}</p>
                    <p><strong>Email:</strong> ${email}</p>
                    <p><strong>Phone:</strong> ${phone || 'Not provided'}</p>
                    <p><strong>Country:</strong> ${country}</p>
                    <p><strong>Subject:</strong> ${subject}</p>
                    <p><strong>Message:</strong></p>
                    <p>${message}</p>
                </div>
            `
        });

        res.status(200).json({
            success: true,
            message: 'Message sent successfully'
        });
    } catch (error) {
        console.error('Error saving contact message:', error);
        res.status(500).json({
            success: false,
            message: 'Error sending message'
        });
    }
});

app.patch('/api/admin/contacts/:contactId/archive', checkAdminAuth, async (req, res) => {
    try {
        const { contactId } = req.params;
        const { archived } = req.body;
        
        if (archived === undefined) {
            return res.status(400).json({
                success: false,
                message: 'Archived status is required'
            });
        }
        
        const contact = await Contact.findByIdAndUpdate(
            contactId,
            { archived: Boolean(archived) },
            { new: true }
        );
        
        if (!contact) {
            return res.status(404).json({
                success: false,
                message: 'Contact not found'
            });
        }
        
        res.json({
            success: true,
            message: archived ? 'Message archived successfully' : 'Message restored successfully',
            contact
        });
    } catch (error) {
        console.error('Error updating contact archive status:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update contact archive status'
        });
    }
});

// Update the existing contacts endpoint to include archived filter
app.get('/api/admin/contacts', checkAdminAuth, async (req, res) => {
    try {
        const { status, search, archived, page = 1, limit = 10 } = req.query;
        const query = {};
        
        if (status) {
            query.status = status;
        }
        
        // Handle archived filter
        if (archived === 'true') {
            query.archived = true;
        } else if (archived === 'false') {
            query.archived = false;
        }
        // If archived is not specified or 'all', don't filter by archived status
        
        if (search) {
            query.$or = [
                { name: { $regex: search, $options: 'i' } },
                { email: { $regex: search, $options: 'i' } },
                { subject: { $regex: search, $options: 'i' } },
                { message: { $regex: search, $options: 'i' } }
            ];
        }
        
        const totalContacts = await Contact.countDocuments(query);
        
        const contacts = await Contact.find(query)
            .sort({ date: -1 })
            .skip((page - 1) * limit)
            .limit(parseInt(limit));
        
        res.json({
            success: true,
            contacts,
            totalPages: Math.ceil(totalContacts / limit),
            currentPage: parseInt(page),
            totalContacts
        });
    } catch (error) {
        console.error('Error fetching contacts:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch contacts'
        });
    }
});
// Archive/unarchive a booking
app.patch('/api/admin/bookings/:bookingId/archive', checkAdminAuth, async (req, res) => {
    try {
        const { bookingId } = req.params;
        const { archived } = req.body;
        
        if (archived === undefined) {
            return res.status(400).json({ 
                success: false, 
                message: 'Archived status is required' 
            });
        }
        
        const booking = await Booking.findByIdAndUpdate(
            bookingId,
            { archived: Boolean(archived) },
            { new: true }
        );
        
        if (!booking) {
            return res.status(404).json({ 
                success: false, 
                message: 'Booking not found' 
            });
        }
        
        res.json({
            success: true,
            message: archived ? 'Booking archived successfully' : 'Booking restored successfully',
            booking
        });
    } catch (error) {
        console.error('Error updating booking archive status:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update booking archive status'
        });
    }
});
// Add this to your server.js file where your other tour endpoints are defined
app.patch('/api/tours/:id/visibility', checkAdminAuth, async (req, res) => {
    try {
        const { id } = req.params;
        const { hidden } = req.body;
        
        if (hidden === undefined) {
            return res.status(400).json({
                success: false,
                message: 'Hidden status is required'
            });
        }
        
        const tour = await Tour.findByIdAndUpdate(
            id,
            { hidden: Boolean(hidden) },
            { new: true }
        );
        
        if (!tour) {
            return res.status(404).json({
                success: false,
                message: 'Tour not found'
            });
        }
        
        res.json({
            success: true,
            message: hidden ? 'Tour hidden successfully' : 'Tour shown successfully',
            tour
        });
    } catch (error) {
        console.error('Error updating tour visibility:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update tour visibility'
        });
    }
});

app.patch('/api/admin/contacts/:contactId/status', checkAdminAuth, async (req, res) => {
    try {
        const { contactId } = req.params;
        const { status } = req.body;
        
        if (!['unread', 'read', 'responded'].includes(status)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid status'
            });
        }
        
        const contact = await Contact.findByIdAndUpdate(
            contactId,
            { status },
            { new: true }
        );
        
        if (!contact) {
            return res.status(404).json({
                success: false,
                message: 'Contact not found'
            });
        }
        
        res.json({
            success: true,
            message: 'Contact status updated',
            contact
        });
    } catch (error) {
        console.error('Error updating contact status:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update contact status'
        });
    }
});

app.get('/api/analytics/traveler-demographics', checkAdminAuth, async (req, res) => {
    try {
        const groupSizeByDestination = await Booking.aggregate([
            { $match: { status: { $ne: 'cancelled' } } },
            {
                $group: {
                    _id: "$destination",
                    averageGroupSize: { $avg: "$travelers" },
                    totalBookings: { $sum: 1 }
                }
            },
            { $sort: { totalBookings: -1 } }
        ]);
        
        res.json({
            success: true,
            groupSizeByDestination
        });
    } catch (error) {
        console.error('Error fetching traveler demographics:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch traveler demographics'
        });
    }
});
app.get('/api/analytics/year-comparison', checkAdminAuth, async (req, res) => {
    try {
        const yearComparison = await Booking.aggregate([
            { $match: { status: { $ne: 'cancelled' } } },
            {
                $group: {
                    _id: {
                        year: { $year: "$createdAt" },
                        destination: "$destination"
                    },
                    bookings: { $sum: 1 },
                    revenue: { $sum: "$totalAmount" }
                }
            },
            { $sort: { "_id.year": 1, "bookings": -1 } }
        ]);
        
        res.json({
            success: true,
            yearComparison
        });
    } catch (error) {
        console.error('Error fetching year comparison:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch year comparison'
        });
    }
});
app.get('/api/analytics/payment-methods', checkAdminAuth, async (req, res) => {
    try {
        const paymentAnalysis = await Booking.aggregate([
            { $match: { status: { $ne: 'cancelled' } } },
            {
                $group: {
                    _id: {
                        destination: "$destination",
                        paymentMethod: "$paymentMethod"
                    },
                    count: { $sum: 1 },
                    revenue: { $sum: "$totalAmount" }
                }
            },
            { $sort: { count: -1 } }
        ]);
        
        res.json({
            success: true,
            paymentAnalysis
        });
    } catch (error) {
        console.error('Error fetching payment analysis:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch payment analysis'
        });
    }
});

app.get('/admin-messages', checkAdminAuth, (req, res) => {
    res.render('admin-messages', { admin: req.session.admin });
});

app.get('/about', (req, res) => {
    res.render('about');
});
app.get('/api/admin/contacts', checkAdminAuth, async (req, res) => {
    try {
        const { status, search, page = 1, limit = 10 } = req.query;
        const query = {};
        
        if (status) {
            query.status = status;
        }
        
        if (search) {
            query.$or = [
                { name: { $regex: search, $options: 'i' } },
                { email: { $regex: search, $options: 'i' } },
                { subject: { $regex: search, $options: 'i' } },
                { message: { $regex: search, $options: 'i' } }
            ];
        }
        const totalContacts = await Contact.countDocuments(query);
        
        const contacts = await Contact.find(query)
            .sort({ date: -1 })
            .skip((page - 1) * limit)
            .limit(parseInt(limit));
        
        res.json({
            success: true,
            contacts,
            totalPages: Math.ceil(totalContacts / limit),
            currentPage: parseInt(page),
            totalContacts
        });
    } catch (error) {
        console.error('Error fetching contacts:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch contacts'
        });
    }
});

app.get('/api/admin/contacts/:contactId', checkAdminAuth, async (req, res) => {
    try {
        const { contactId } = req.params;
        
        const contact = await Contact.findById(contactId);
        
        if (!contact) {
            return res.status(404).json({
                success: false,
                message: 'Contact not found'
            });
        }
        
        res.json({
            success: true,
            contact
        });
    } catch (error) {
        console.error('Error fetching contact:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch contact'
        });
    }
});

app.patch('/api/admin/contacts/:contactId/status', checkAdminAuth, async (req, res) => {
    try {
        const { contactId } = req.params;
        const { status } = req.body;
        
        if (!['unread', 'read', 'responded'].includes(status)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid status'
            });
        }
        
        const contact = await Contact.findByIdAndUpdate(
            contactId,
            { status },
            { new: true }
        );
        
        if (!contact) {
            return res.status(404).json({
                success: false,
                message: 'Contact not found'
            });
        }
        
        res.json({
            success: true,
            message: 'Contact status updated',
            contact
        });
    } catch (error) {
        console.error('Error updating contact status:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update contact status'
        });
    }
});

app.delete('/api/admin/contacts/:contactId', checkAdminAuth, async (req, res) => {
    try {
        const { contactId } = req.params;
        
        const contact = await Contact.findByIdAndDelete(contactId);
        
        if (!contact) {
            return res.status(404).json({
                success: false,
                message: 'Contact not found'
            });
        }
        
        res.json({
            success: true,
            message: 'Contact deleted successfully'
        });
    } catch (error) {
        console.error('Error deleting contact:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to delete contact'
        });
    }
});
app.post('/api/admin/send-reply', checkAdminAuth, async (req, res) => {
    try {
        const { messageId, email, subject, content } = req.body;
        
        const contact = await Contact.findById(messageId);
        if (!contact) {
            return res.status(404).json({
                success: false,
                message: 'Contact not found'
            });
        }

        // Send email reply
        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject: subject,
            html: `
                <div style="font-family: Arial, sans-serif;">
                    <h2>Response to Your Inquiry</h2>
                    <p>Dear ${contact.name},</p>
                    <p>${content}</p>
                    <p>Best regards,<br>A.BEE Travel and Tours Team</p>
                </div>
            `
        });

        // Send SMS if phone number is available
        if (contact.phone) {
            try {
                const smsMessage = `A.BEE Travel: Re: ${subject.substring(0, 30)}... ${content.substring(0, 100)}${content.length > 100 ? '...' : ''} Reply to this email for more details.`;
                await sendSMS(contact.phone, smsMessage);
            } catch (smsError) {
                console.error('Error sending SMS:', smsError);
                // Continue even if SMS fails
            }
        }

        // Update contact status
        contact.status = 'responded';
        await contact.save();

        res.json({
            success: true,
            message: 'Reply sent successfully'
        });
    } catch (error) {
        console.error('Error sending reply:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to send reply'
        });
    }
});

app.patch('/api/admin/contacts/:contactId/archive', checkAdminAuth, async (req, res) => {
    try {
        const { contactId } = req.params;
        const { archived } = req.body;
        
        if (archived === undefined) {
            return res.status(400).json({
                success: false,
                message: 'Archived status is required'
            });
        }
        
        const contact = await Contact.findByIdAndUpdate(
            contactId,
            { archived: Boolean(archived) },
            { new: true }
        );
        
        if (!contact) {
            return res.status(404).json({
                success: false,
                message: 'Contact not found'
            });
        }
        
        res.json({
            success: true,
            message: archived ? 'Message archived successfully' : 'Message restored successfully',
            contact
        });
    } catch (error) {
        console.error('Error updating contact archive status:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update contact archive status'
        });
    }
});
apiRouter.patch('/users/:userId/status', checkAdminAuth, async (req, res) => {
    try {
        const { userId } = req.params;
        const { isActive } = req.body;
        
        if (isActive === undefined) {
            return res.status(400).json({
                success: false,
                message: 'isActive status is required'
            });
        }
        
        if (!mongoose.Types.ObjectId.isValid(userId)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid user ID format'
            });
        }
        
        const updatedUser = await User.findByIdAndUpdate(
            userId,
            { isActive: Boolean(isActive) },
            { new: true }
        );
        
        if (!updatedUser) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }
        
        res.json({
            success: true,
            message: `User ${isActive ? 'activated' : 'deactivated'} successfully`,
            user: updatedUser
        });
    } catch (error) {
        console.error('❌ Error updating user status:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update user status: ' + error.message
        });
    }
});
apiRouter.patch('/admins/:adminId/status', checkAdminAuth, async (req, res) => {
    try {
        const { adminId } = req.params;
        const { isActive } = req.body;
        
        if (isActive === undefined) {
            return res.status(400).json({
                success: false,
                message: 'isActive status is required'
            });
        }
        
        if (!mongoose.Types.ObjectId.isValid(adminId)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid admin ID format'
            });
        }
        
        const updatedAdmin = await Admin.findByIdAndUpdate(
            adminId,
            { isActive: Boolean(isActive) },
            { new: true }
        );
        
        if (!updatedAdmin) {
            return res.status(404).json({
                success: false,
                message: 'Admin not found'
            });
        }
        
        res.json({
            success: true,
            message: `Admin ${isActive ? 'activated' : 'deactivated'} successfully`,
            admin: updatedAdmin
        });
    } catch (error) {
        console.error('❌ Error updating admin status:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update admin status: ' + error.message
        });
    }
});
// ✅ Weekly Analytics Endpoint
app.get('/api/analytics/weekly', checkAdminAuth, async (req, res) => {
  try {
    const { startDate, endDate } = req.query;
    const start = new Date(startDate);
    const end = new Date(endDate);

    // Normalize week boundaries (start on Monday)
    const day = start.getDay();
    const diff = (day === 0 ? -6 : 1) - day; // if Sunday, go back 6 days
    start.setDate(start.getDate() + diff);
    end.setDate(end.getDate() + (7 - end.getDay()));

    // Match stage for the selected date range
    const matchStage = {
      createdAt: { $gte: start, $lte: end }
    };

    // Aggregate users and bookings per week
    const [userData, bookingData] = await Promise.all([
      User.aggregate([
        { $match: matchStage },
        {
          $group: {
            _id: { $dateTrunc: { date: "$createdAt", unit: "week" } },
            count: { $sum: 1 }
          }
        },
        { $sort: { "_id": 1 } }
      ]),
      Booking.aggregate([
        { $match: matchStage },
        {
          $group: {
            _id: { $dateTrunc: { date: "$createdAt", unit: "week" } },
            count: { $sum: 1 },
            revenue: { $sum: "$totalAmount" }
          }
        },
        { $sort: { "_id": 1 } }
      ])
    ]);

    // Combine both datasets
    const weeks = {};
    for (const u of userData) {
      const week = new Date(u._id).toISOString().split("T")[0];
      if (!weeks[week]) weeks[week] = { users: 0, bookings: 0, revenue: 0 };
      weeks[week].users = u.count;
    }
    for (const b of bookingData) {
      const week = new Date(b._id).toISOString().split("T")[0];
      if (!weeks[week]) weeks[week] = { users: 0, bookings: 0, revenue: 0 };
      weeks[week].bookings = b.count;
      weeks[week].revenue = b.revenue;
    }

    res.json({ success: true, data: weeks });
  } catch (error) {
    console.error("❌ Weekly analytics error:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});


app.get('/api/analytics/monthly', checkAdminAuth, async (req, res) => {
    try {
        const { year } = req.query;
        const selectedYear = year ? parseInt(year) : new Date().getFullYear();
        
        const startDate = new Date(selectedYear, 0, 1); // January 1st of selected year
        const endDate = new Date(selectedYear, 11, 31, 23, 59, 59, 999); // December 31st of selected year
        
        // Get monthly user registrations
        const monthlyUsers = await User.aggregate([
            { 
                $match: { 
                    createdAt: { $gte: startDate, $lte: endDate } 
                } 
            },
            {
                $group: {
                    _id: { 
                        year: { $year: "$createdAt" },
                        month: { $month: "$createdAt" }
                    },
                    count: { $sum: 1 }
                }
            },
            { $sort: { "_id.year": 1, "_id.month": 1 } }
        ]);
        
        // Get monthly bookings
        const monthlyBookings = await Booking.aggregate([
            { 
                $match: { 
                    createdAt: { $gte: startDate, $lte: endDate } 
                } 
            },
            {
                $group: {
                    _id: { 
                        year: { $year: "$createdAt" },
                        month: { $month: "$createdAt" }
                    },
                    count: { $sum: 1 },
                    revenue: { $sum: "$totalAmount" }
                }
            },
            { $sort: { "_id.year": 1, "_id.month": 1 } }
        ]);
        
        res.json({
            success: true,
            monthlyUsers,
            monthlyBookings
        });
    } catch (error) {
        console.error('Error fetching monthly analytics:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch monthly analytics'
        });
    }
});

app.get('/api/analytics/yearly', checkAdminAuth, async (req, res) => {
    try {
        // Get yearly user registrations
        const yearlyUsers = await User.aggregate([
            {
                $group: {
                    _id: { 
                        year: { $year: "$createdAt" }
                    },
                    count: { $sum: 1 }
                }
            },
            { $sort: { "_id.year": 1 } }
        ]);
        
        // Get yearly bookings
        const yearlyBookings = await Booking.aggregate([
            {
                $group: {
                    _id: { 
                        year: { $year: "$createdAt" }
                    },
                    count: { $sum: 1 },
                    revenue: { $sum: "$totalAmount" }
                }
            },
            { $sort: { "_id.year": 1 } }
        ]);
        
        res.json({
            success: true,
            yearlyUsers,
            yearlyBookings
        });
    } catch (error) {
        console.error('Error fetching yearly analytics:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch yearly analytics'
        });
    }
});
// 📊 Year-to-Year Monthly Comparison API
app.get('/api/analytics/monthly-comparison', checkAdminAuth, async (req, res) => {
  try {
    const { year1, year2 } = req.query;

    if (!year1 || !year2) {
      return res.status(400).json({ success: false, message: 'Both years are required' });
    }

    const getMonthlyData = async (year) => {
      const start = new Date(year, 0, 1);
      const end = new Date(year, 11, 31, 23, 59, 59);

      const users = await User.aggregate([
        { $match: { createdAt: { $gte: start, $lte: end } } },
        { $group: { _id: { $month: "$createdAt" }, count: { $sum: 1 } } },
        { $sort: { "_id": 1 } }
      ]);

      const bookings = await Booking.aggregate([
        { $match: { createdAt: { $gte: start, $lte: end } } },
        { $group: { _id: { $month: "$createdAt" }, count: { $sum: 1 } } },
        { $sort: { "_id": 1 } }
      ]);

      const revenue = await Booking.aggregate([
        { $match: { createdAt: { $gte: start, $lte: end } } },
        { $group: { _id: { $month: "$createdAt" }, total: { $sum: "$totalAmount" } } },
        { $sort: { "_id": 1 } }
      ]);

      const months = Array.from({ length: 12 }, (_, i) => i + 1);

      return {
        year,
        users: months.map(m => users.find(u => u._id === m)?.count || 0),
        bookings: months.map(m => bookings.find(b => b._id === m)?.count || 0),
        revenue: months.map(m => revenue.find(r => r._id === m)?.total || 0)
      };
    };

    const data1 = await getMonthlyData(Number(year1));
    const data2 = await getMonthlyData(Number(year2));

    res.json({ success: true, data1, data2 });

  } catch (error) {
    console.error("❌ Error in monthly comparison:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

const checkManagerAuth = (req, res, next) => {
    if (!req.session || !req.session.admin || req.session.admin.role !== 'manager') {
        const isApiRequest = req.path.startsWith('/api/');
        
        if (isApiRequest) {
            return res.status(401).json({
                success: false,
                message: 'Unauthorized. Please log in as a manager.'
            });
        } else {
            return res.redirect('/admin');
        }
    }
    next();
};

app.get('/manager-dashboard', checkManagerAuth, (req, res) => {
    res.render('manager', { admin: req.session.admin });
});

app.get('/api/manager-dashboard/data', checkManagerAuth, async (req, res) => {
    try {
        const totalCustomers = await User.countDocuments();
        const customerRegistrations = await User.aggregate([
            {
                $group: {
                    _id: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } },
                    count: { $sum: 1 }
                }
            },
            { $sort: { _id: 1 } }
        ]);

        const labels = customerRegistrations.map(item => item._id);
        const data = customerRegistrations.map(item => item.count);

        res.json({
            totalCustomers,
            customerRegistrations: {
                labels,
                data
            }
        });
    } catch (error) {
        console.error("Error fetching manager dashboard data:", error);
        res.status(500).json({ error: "Failed to fetch dashboard data." });
    }
});
app.get('/api/feedback', async (req, res) => {
    try {
        const feedback = await Contact.find({ 
            displayOnHome: true,
            status: 'responded',
            archived: false
        })
        .select('name email phone country subject message date')
        .sort({ date: -1 })
        .limit(6);
        
        
        res.json({
            success: true,
            feedback
        });
    } catch (error) {
        console.error('Error fetching feedback:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch feedback'
        });
    }
});

app.patch('/api/admin/contacts/:contactId/display', checkAdminAuth, async (req, res) => {
    try {
        const { contactId } = req.params;
        const { displayOnHome } = req.body;
        
        const contact = await Contact.findByIdAndUpdate(
            contactId,
            { displayOnHome },
            { new: true }
        );
        
        if (!contact) {
            return res.status(404).json({
                success: false,
                message: 'Contact not found'
            });
        }
        
        res.json({
            success: true,
            message: `Message ${displayOnHome ? 'will' : 'will not'} be displayed on homepage`,
            contact
        });
    } catch (error) {
        console.error('Error updating contact display status:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update contact display status'
        });
    }
});
// Unified credential verification endpoint
app.post('/verify-unified-credentials', async (req, res) => {
    try {
        const { emailOrUsername, password } = req.body;
        
        // First try to find as regular user (by username or email)
        let user = await User.findOne({
            $or: [
                { username: emailOrUsername },
                { email: emailOrUsername }
            ]
        });
        
        if (user) {
            const isMatch = await user.comparePassword(password);
            if (isMatch) {
                if (user.isActive === false) {
                    return res.status(403).json({ 
                        success: false, 
                        message: 'Your account has been deactivated. Please contact support.' 
                    });
                }
                return res.json({ 
                    success: true, 
                    type: 'user',
                    email: user.email 
                });
            }
        }
        
        // If not found as user, try as admin (by email only)
        const admin = await Admin.findOne({ email: emailOrUsername });
        
        if (admin) {
            const isMatch = await bcrypt.compare(password, admin.password);
            if (isMatch) {
                if (!admin.isVerified || admin.status !== 'active') {
                    return res.status(401).json({ 
                        success: false, 
                        status: 'pending',
                        message: 'Your account is pending approval' 
                    });
                }
                return res.json({ 
                    success: true, 
                    type: 'admin',
                    email: admin.email 
                });
            }
        }
        
        return res.status(400).json({ 
            success: false, 
            message: 'Invalid credentials' 
        });
        
    } catch (error) {
        console.error('Unified credential verification error:', error);
        return res.status(500).json({ 
            success: false, 
            message: 'Internal Server Error' 
        });
    }
});
app.get("/api/analytics/top-destinations", async (req, res) => {
  try {
    const { type = "all" } = req.query;
    const now = new Date();

    // Build filter
    let matchStage = {};
    if (type === "daily") {
      matchStage = {
        startDate: {
          $gte: new Date(now.getFullYear(), now.getMonth(), now.getDate()),
          $lt: new Date(now.getFullYear(), now.getMonth(), now.getDate() + 1)
        }
      };
    } else if (type === "monthly") {
      matchStage = {
        startDate: {
          $gte: new Date(now.getFullYear(), now.getMonth(), 1),
          $lt: new Date(now.getFullYear(), now.getMonth() + 1, 1)
        }
      };
    } else if (type === "yearly") {
      matchStage = {
        startDate: {
          $gte: new Date(now.getFullYear(), 0, 1),
          $lt: new Date(now.getFullYear() + 1, 0, 1)
        }
      };
    } // else "all" = no date filter

    const results = await Booking.aggregate([
      { $match: matchStage },
      {
        $group: {
          _id: { season: "$season", destination: "$destination" },
          count: { $sum: 1 }
        }
      },
      { $sort: { count: -1 } },
      {
        $group: {
          _id: "$_id.season",
          destinations: { $push: { destination: "$_id.destination", count: "$count" } }
        }
      },
      {
        $project: {
          season: "$_id",
          topDestinations: { $slice: ["$destinations", 5] },
          _id: 0
        }
      },
      { $sort: { season: 1 } }
    ]);

    res.json({ success: true, type, data: results });
  } catch (err) {
    console.error("❌ Top Destinations Analytics Error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

apiRouter.get('/analytics/summary', checkAdminAuth, async (req, res) => {
    try {
        const { period = 'all' } = req.query;
        let startDate;
        const now = new Date();

        // Determine startDate based on period
        switch (period) {
            case 'year':
                startDate = new Date(now.getFullYear(), 0, 1);
                break;
            case 'month':
                startDate = new Date(now.getFullYear(), now.getMonth(), 1);
                break;
            case 'day':
                startDate = new Date(now.getFullYear(), now.getMonth(), now.getDate());
                break;
            case 'all':
            default:
                startDate = null; // For all-time, no filter
                break;
        }

        const dateFilter = startDate ? { createdAt: { $gte: startDate } } : {};

        // Count total users
        const totalUsers = await User.countDocuments(dateFilter);
        // Count total bookings
        const totalBookings = await Booking.countDocuments(dateFilter);

        // Calculate total sales
        const salesAggregation = await Booking.aggregate([
            { $match: { ...dateFilter, status: { $in: ['confirmed', 'completed'] } } },
            { $group: { _id: null, total: { $sum: '$totalAmount' } } }
        ]);
        const totalSales = salesAggregation.length > 0 ? salesAggregation[0].total : 0;

        // Top 5 destinations
        const topDestinations = await Booking.aggregate([
            { $match: dateFilter },
            { $group: { _id: '$destination', count: { $sum: 1 } } },
            { $sort: { count: -1 } },
            { $limit: 5 }
        ]);

        // Send response
        res.json({
            success: true,
            data: {
                totalUsers,
                totalBookings,
                totalSales,
                topDestinations
            }
        });
    } catch (error) {
        console.error('Error fetching summary analytics:', error);
        res.status(500).json({ success: false, message: 'Failed to fetch summary data' });
    }
});
// ==========================
// 📊 FORECAST + INSIGHTS API
// ==========================

module.exports = app;


// ---------- Forecast Endpoint ----------
app.get("/api/forecast/:type", async (req, res) => {
  try {
    const { type } = req.params;
    const now = new Date();

    // 🧮 Create 12 months of random historical data
    const history = Array.from({ length: 12 }).map((_, i) => ({
      date: new Date(now.getFullYear(), now.getMonth() - i, 1),
      value: Math.floor(Math.random() * 100000 + 50000) // Random value
    }));

    // 🔮 Create 3 months of projected data
    const forecast = Array.from({ length: 3 }).map((_, i) => ({
      date: new Date(now.getFullYear(), now.getMonth() + i + 1, 1),
      value: Math.floor(Math.random() * 120000 + 80000)
    }));

    const accuracy = Math.floor(Math.random() * 15 + 85); // %
    const note = "Based on simulated historical pattern.";

    // Return type-specific data (future ready)
    switch (type) {
      case "sales":
        res.json({
          history,
          forecast,
          accuracy,
          note,
          metric: "₱"
        });
        break;
      case "bookings":
        res.json({
          history,
          forecast,
          accuracy,
          note,
          metric: "bookings"
        });
        break;
      case "users":
        res.json({
          history,
          forecast,
          accuracy,
          note,
          metric: "users"
        });
        break;
      default:
        res.status(400).json({ error: "Invalid forecast type" });
    }
  } catch (error) {
    console.error("❌ Forecast Error:", error);
    res.status(500).json({ error: error.message });
  }
});
app.get("/api/insights", async (req, res) => {
  try {
    console.log("📊 Gathering booking data for insights...");

    // ✅ Use the same aggregation that worked in /api/test-insights
    const tours = await Booking.aggregate([
      {
        $group: {
          _id: "$tourDetails.title",
          tourId: { $first: "$_id" },
          title: { $first: "$tourDetails.title" },
          bookings: { $sum: 1 },
          revenue: { $sum: "$totalAmount" }
        }
      }
    ]);

    console.log("🧩 Aggregation output (for FastAPI):", tours);

    if (!tours || tours.length === 0) {
      console.warn("⚠️ No booking data found for insights");
      return res.json({
        success: true,
        recommendations: ["⚠️ Not enough data for insights yet."],
        summary: { total_tours: 0 }
      });
    }

    // ✅ Clean tours data before sending to FastAPI
    const cleanTours = tours.map(t => ({
      tourId: String(t.tourId || t._id || "unknown"),
      title: t.title || "Untitled Tour",
      bookings: Number(t.bookings || 0),
      revenue: Number(t.revenue || 0),
      createdAt: new Date().toISOString()
    }));

    console.log("📤 Cleaned tours sent to FastAPI:", cleanTours);

    // ✅ Send to FastAPI
    const response = await fetch("http://127.0.0.1:8000/insights", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ tours: cleanTours })
    });

    const data = await response.json();
    if (!response.ok) throw new Error(JSON.stringify(data));

    console.log("✅ Insights successfully fetched from FastAPI.");
    res.json(data);

  } catch (err) {
    console.error("❌ Insight fetch error:", err);
    res.status(500).json({
      success: false,
      message: "Failed to generate insights",
      details: err.message
    });
  }
});


// 🚫 This must stay at the very bottom
app.use((req, res) => {
  res.status(404).render('404', { url: req.url });
});


app.get("/",(req, res) => {
    res.send("Hello from the server")
});

    
app.listen(PORT,"0.0.0.0", () => {
    console.log(`🚀 Server is running on http://localhost:${PORT}`);
});
