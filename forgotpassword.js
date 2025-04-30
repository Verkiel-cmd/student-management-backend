import express from 'express';
import mysql from 'mysql2';
import cors from 'cors';
import nodemailer from 'nodemailer';
import dotenv from 'dotenv';
import bcrypt from 'bcrypt';
import config from './config.js';
dotenv.config();



const app = express();

app.use((req, res, next) => {
    console.log(`Request URL: ${req.url}`);
    console.log(`Request Method: ${req.method}`);
    console.log(`Request Headers: ${JSON.stringify(req.headers)}`);
    next();
});


app.use(cors({
    origin: 'https://student-management-frontend-xhec.vercel.app/', // Replace with your frontend's URL
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    credentials: true
}));

app.use(express.json());


const db = mysql.createConnection({
    host: config.DB_HOST,        // MYSQLHOST from Render's environment
    user: config.DB_USER,        // MYSQLUSER from Render's environment
    password: config.DB_PASSWORD, // MYSQLPASSWORD from Render's environment
    database: config.DB_NAME,     // MYSQL_DATABASE from Render's environment
    port: process.env.MYSQLPORT || 3306, // Optional: use MYSQLPORT if you have a custom port
});

const dbPromise = db.promise();

db.connect(err => {
    if (err) {
        console.error('Error connecting to database:', err);
        return;
    }
    console.log('Connected to MySQL database');
});

//storage for OTPs 
const otpStorage = new Map();

// Configure nodemailer transporter
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
    tls: {
        rejectUnauthorized: false,
    },
    debug: true,
});
const generateOTP = () => {
    return Math.floor(100000 + Math.random() * 900000).toString();
};


app.post('/send-otp', async (req, res) => {
    const { email } = req.body;

    try {

        const isValidEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
        if (!isValidEmail(email)) {
            return res.status(400).json({ success: false, message: 'Invalid email address' });
        }


        const [users] = await dbPromise.query('SELECT * FROM users WHERE email = ?', [email]);
        if (users.length === 0) {
            return res.status(404).json({ success: false, message: 'Email not found' });
        }


        const otp = generateOTP();


        otpStorage.set(email, {
            otp,
            expires: Date.now() + 10 * 60 * 1000
        });


        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Password Reset OTP',
            text: `Your OTP for password reset is: ${otp}. It will expire in 10 minutes.`
        });

        res.json({ success: true, message: 'OTP sent successfully' });
    } catch (error) {
        console.error('Error in /send-otp:', error); // Log the error
        res.status(500).json({ success: false, message: 'Failed to send OTP' });
    }
});

// Verify OTP Route
app.post('/verify-otp', (req, res) => {
    const { email, otp } = req.body;

    const storedOTP = otpStorage.get(email);

    if (!storedOTP) {
        return res.status(400).json({ success: false, message: 'OTP not found' });
    }

    if (storedOTP.expires < Date.now()) {
        otpStorage.delete(email);
        return res.status(400).json({ success: false, message: 'OTP expired' });
    }

    if (storedOTP.otp !== otp) {
        return res.status(400).json({ success: false, message: 'Invalid OTP' });
    }


    otpStorage.delete(email);

    res.json({ success: true, message: 'OTP verified successfully' });
});

// Reset Password Route
app.post('/reset-password', async (req, res) => {
    const { email, newPassword } = req.body;

    try {

        const [user] = await dbPromise.query('SELECT * FROM users WHERE email = ?', [email]);
        if (!user || user.length === 0) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }



        const hashedPassword = await bcrypt.hash(newPassword, 10);


        user.password = hashedPassword;

        await dbPromise.query('UPDATE users SET password = ? WHERE email = ?', [hashedPassword, email]);

        res.json({ success: true, message: 'Password reset successfully' });
    } catch (error) {
        console.error('Error in /reset-password:', error);
        res.status(500).json({ success: false, message: 'Failed to reset password' });
    }
});



//Start the server
// In class.js, forgotpassword.js, login.js, serverList.js
const PORT = process.env.PORT || 7000; // Use 5000 as fallback for local dev
app.listen(PORT, (err) => {
    if (err) {
        console.error('Failed to start server:', err.message);
    } else {
        console.log(`Server running on port ${PORT}`);
    }
});






