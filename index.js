import express from 'express';
import mysql from 'mysql2';
import cors from 'cors';
import bcrypt from 'bcrypt';
import session from 'express-session';
import MySQLSession from 'express-mysql-session';
import { OAuth2Client } from 'google-auth-library';
import nodemailer from 'nodemailer';
import dotenv from 'dotenv';
import config from './config.js';


dotenv.config();

const app = express();

app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', 
    "default-src 'self'; " +
    "script-src 'self' https://accounts.google.com https://apis.google.com; " +
    "frame-src https://accounts.google.com; " +
    "connect-src 'self' https://accounts.google.com https://oauth2.googleapis.com;" 
  );
  
  res.setHeader('Access-Control-Allow-Origin', 'https://student-management-st.netlify.app');
  res.setHeader('Access-Control-Allow-Credentials', 'true');

  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN'); // Allow iframes from same origin
  res.setHeader('X-XSS-Protection', '1; mode=block');

  // res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  // res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp'); 

  next();
});

// CORS Configuration
app.use(cors({
    origin: (origin, callback) => {
        const allowedOrigins = [
            'https://student-management-st.netlify.app',
        ];
        console.log('Allowed Origins:', allowedOrigins); // Debug log
        console.log('Request Origin:', origin); // Debug log
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            console.error(`CORS blocked for origin: ${origin}`);
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    optionsSuccessStatus: 204 // Handle preflight OPTIONS requests
}));

app.use(express.json());

// --- Middleware ---
app.use((req, res, next) => {
    console.log(`Request URL: ${req.url}`);
    console.log(`Request Method: ${req.method}`);
    console.log(`Request Headers: ${JSON.stringify(req.headers)}`);
    next();
});



// --- MySQL Connection ---
const db = mysql.createPool({
    host: config.DB_HOST,
    user: config.DB_USER,
    password: config.DB_PASSWORD,
    database: config.DB_NAME,
    port: config.MYSQLPORT || process.env.MYSQLPORT || 53382,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});
const dbPromise = db.promise();

// --- Session Store ---
const MySQLStore = MySQLSession(session);
const sessionStore = new MySQLStore({
    host: config.DB_HOST,
    user: config.DB_USER,
    password: config.DB_PASSWORD,
    database: config.DB_NAME,
    port: config.MYSQLPORT || process.env.MYSQLPORT || 53382,
    clearExpired: true,
    checkExpirationInterval: 900000,
    expiration: 86400000,
});

// Add this line BEFORE app.use(session(...))
app.set('trust proxy', 1);

app.use(session({
    name: 'user_sid',
    secret: config.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: sessionStore,
    cookie: {
        secure: config.NODE_ENV === 'production',
        httpOnly: true,
        sameSite: 'none',
        maxAge: 1000 * 60 * 60 * 24
    }
}));

// --- Root Route ---
app.get('/', (req, res) => {
    res.send('Welcome to the Student Management API!');
});

// Registration
app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;
    try {
        const [existingUsers] = await dbPromise.query(
            'SELECT * FROM users WHERE email = ? OR username = ?',
            [email, username]
        );
        if (existingUsers.length > 0) {
            return res.status(400).json({
                success: false,
                message: existingUsers[0].email === email
                    ? 'Email already in use'
                    : 'Username already exists'
            });
        }
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        const [result] = await dbPromise.query(
            'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
            [username, email, hashedPassword]
        );
        req.session.userId = result.insertId;
        req.session.username = username;
        console.log('Before save:', req.session);
        // Change: Use a Promise to wait for the session to save
        await new Promise((resolve, reject) => {
            req.session.save(err => {
                if (err) {
                    console.error('Session save error:', err);
                    return reject(err);
                }
                console.log('After save:', req.session);
                resolve();
            });
        });
        const [users] = await dbPromise.query('SELECT * FROM users WHERE id = ?', [result.insertId]);
        const newUser = users[0];
        res.status(201).json({
            success: true,
            message: 'User registered successfully',
            userId: newUser.id,
            username: newUser.username,
            email: newUser.email,
            redirectUrl: '/Student_lists/ListStud'
});
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ success: false, message: 'Server error. Please try again later.' });
    }
});
// Login
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const [users] = await dbPromise.query('SELECT * FROM users WHERE email = ?', [email]);
        if (users.length === 0) {
            return res.status(400).json({
                success: false,
                messageEmail: 'Invalid email',
                field: 'email'
            });
        }
        const user = users[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({
                success: false,
                messagePassword: 'Invalid password',
                field: 'password'
            });
        }
        req.session.userId = user.id;
        req.session.username = user.username;
        console.log('Before save:', req.session);
        // Change: Use a Promise to wait for the session to save
        await new Promise((resolve, reject) => {
            req.session.save(err => {
                if (err) {
                    console.error('Session save error:', err);
                    return reject(err);
                }
                console.log('After save:', req.session);
                resolve();
            });
        });
        res.json({
            success: true,
            message: 'Login successful',
            userId: user.id,
            username: user.username,
            redirectUrl: '/Student_lists/ListStud'
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ success: false, message: 'Server error. Please try again later.' });
    }
});

app.get('/auth/validate', (req, res) => {
    console.log('Session in /auth/validate:', req.session);
    if (req.session && req.session.userId) {
        return res.status(200).json({
            authenticated: true,
            user: {
                id: req.session.userId,
                username: req.session.username
            }
        });
    } else {
        return res.status(200).json({ authenticated: false });
    }
});


// Logout
app.post('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) return res.status(500).json({ error: "Logout failed" });
        res.clearCookie('user_sid', {
            sameSite: 'none',
            secure: process.env.NODE_ENV === 'production'
        });
        res.json({ message: "Logout successful" });
    });
});

// Google Sign-In
app.post('/google-login', async (req, res) => {
    console.log('Handling /google-login POST');
    const { token } = req.body;
    
    if (!token) {
        return res.status(400).json({
            success: false,
            message: 'No token provided'
        });
    }

    try {
        const client = new OAuth2Client(config.GOOGLE_CLIENT_ID);
        const ticket = await client.verifyIdToken({
            idToken: token,
            audience: config.GOOGLE_CLIENT_ID,
        });
        const payload = ticket.getPayload();
        
        if (!payload.email) {
            return res.status(400).json({
                success: false,
                message: 'Email not provided by Google'
            });
        }

        const email = payload.email;
        const name = payload.name || email.split('@')[0];
        const picture = payload.picture || null;

        try {
            // Check if user exists
            const [users] = await dbPromise.query('SELECT * FROM users WHERE email = ?', [email]);
            
            if (users.length === 0) {
                // Create new user with a generated username
                const username = name.replace(/[^a-zA-Z0-9]/g, '').toLowerCase();
                const [result] = await dbPromise.query(
                    'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                    [username, email, '']
                );
                
                // Set up session
                req.session.userId = result.insertId;
                req.session.username = username;
                
                await new Promise((resolve, reject) => {
                    req.session.save(err => {
                        if (err) reject(err);
                        else resolve();
                    });
                });

                return res.status(200).json({
                    success: true,
                    message: 'Google login successful',
                    userId: result.insertId,
                    username: username,
                    email: email,
                    picture: picture,
                    redirectUrl: '/Student_lists/ListStud'
                });
            } else {
                // Existing user - set up session
                const user = users[0];
                req.session.userId = user.id;
                req.session.username = user.username;
                
                await new Promise((resolve, reject) => {
                    req.session.save(err => {
                        if (err) reject(err);
                        else resolve();
                    });
                });

                return res.status(200).json({
                    success: true,
                    message: 'Google login successful',
                    userId: user.id,
                    username: user.username,
                    email: user.email,
                    picture: picture,
                    redirectUrl: '/Student_lists/ListStud'
                });
            }
        } catch (dbError) {
            console.error('Database error during Google login:', dbError);
            return res.status(500).json({ 
                success: false, 
                message: 'Database error during login',
                error: process.env.NODE_ENV === 'development' ? dbError.message : undefined
            });
        }
    } catch (error) {
        console.error('Google token verification error:', error);
        return res.status(401).json({ 
            success: false,
            message: 'Invalid Google token',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// Session info
app.get('/session', (req, res) => {
    if (req.session.username) {
        res.json({ username: req.session.username });
    } else {
        res.status(401).json({ message: 'Not logged in' });
    }
});

// Check username
app.post('/check-username', async (req, res) => {
    const { username } = req.body;
    try {
        const [existingUsers] = await dbPromise.query(
            'SELECT * FROM users WHERE username = ?',
            [username]
        );
        if (existingUsers.length > 0) {
            return res.json({ exists: true });
        } else {
            return res.json({ exists: false });
        }
    } catch (error) {
        res.status(500).json({ exists: false, message: 'Server error' });
    }
});

// ===================
// FORGOT PASSWORD / OTP ROUTES
// ===================

const otpStorage = new Map();

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    },
    tls: {
        rejectUnauthorized: true
    }
});

// Test email configuration on startup
transporter.verify(function(error, success) {
    if (error) {
        console.error('Email configuration error:', error);
       
    } else {
        console.log('Email server is ready to send messages');
    }
});

const generateOTP = () => Math.floor(100000 + Math.random() * 900000).toString();

app.post('/send-otp', async (req, res) => {
    const { email } = req.body;
    
    // Input validation
    if (!email) {
        return res.status(400).json({ 
            success: false, 
            message: 'Email is required' 
        });
    }

    const isValidEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
    if (!isValidEmail(email)) {
        return res.status(400).json({ 
            success: false, 
            message: 'Invalid email address' 
        });
    }

    try {
        // Check if user exists
        const [users] = await dbPromise.query('SELECT * FROM users WHERE email = ?', [email]);
        if (users.length === 0) {
            return res.status(404).json({ 
                success: false, 
                message: 'Email not found in our records' 
            });
        }

        // Generate and store OTP
        const otp = generateOTP();
        otpStorage.set(email, { 
            otp, 
            expires: Date.now() + 10 * 60 * 1000,
            attempts: 0
        });

        // Send email
        try {
            const mailOptions = {
                from: `"Student Management System" <${process.env.EMAIL_USER}>`,
                to: email,
                subject: 'Password Reset OTP',
                text: `Your OTP for password reset is: ${otp}. It will expire in 10 minutes.`,
                html: `
                    <div style="font-family: Arial, sans-serif; padding: 20px; max-width: 600px; margin: 0 auto;">
                        <h2 style="color: #333;">Password Reset Request</h2>
                        <p>Your OTP for password reset is:</p>
                        <h1 style="color: #007bff; font-size: 32px; letter-spacing: 5px;">${otp}</h1>
                        <p>This OTP will expire in 10 minutes.</p>
                        <p>If you didn't request this, please ignore this email.</p>
                    </div>
                `
            };

            const info = await transporter.sendMail(mailOptions);
            console.log('Email sent successfully:', info.messageId);

            res.json({ 
                success: true, 
                message: 'OTP sent successfully',
                email: email
            });
        } catch (emailError) {
            console.error('Email sending error details:', {
                error: emailError,
                code: emailError.code,
                command: emailError.command,
                response: emailError.response,
                responseCode: emailError.responseCode
            });
            
            // Remove the OTP if email sending fails
            otpStorage.delete(email);
            
            return res.status(500).json({ 
                success: false, 
                message: 'Failed to send OTP email. Please try again later.',
                error: process.env.NODE_ENV === 'development' ? emailError.message : undefined
            });
        }
    } catch (error) {
        console.error('OTP generation error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to process OTP request. Please try again later.',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

app.post('/verify-otp', async (req, res) => {
    const { email, otp } = req.body;
    
    if (!email || !otp) {
        return res.status(400).json({ 
            success: false, 
            message: 'Email and OTP are required' 
        });
    }

    try {
        // First check if user exists
        const [users] = await dbPromise.query('SELECT * FROM users WHERE email = ?', [email]);
        if (users.length === 0) {
            return res.status(404).json({ 
                success: false, 
                message: 'User not found' 
            });
        }

        const storedOTP = otpStorage.get(email);
        if (!storedOTP) {
            return res.status(400).json({ 
                success: false, 
                message: 'No OTP found for this email. Please request a new OTP.' 
            });
        }

        if (storedOTP.expires < Date.now()) {
            otpStorage.delete(email);
            return res.status(400).json({ 
                success: false, 
                message: 'OTP has expired. Please request a new one.' 
            });
        }

        if (storedOTP.otp !== otp) {
            // Increment attempts
            storedOTP.attempts = (storedOTP.attempts || 0) + 1;
            otpStorage.set(email, storedOTP);

            if (storedOTP.attempts >= 3) {
                otpStorage.delete(email);
                return res.status(400).json({ 
                    success: false, 
                    message: 'Too many failed attempts. Please request a new OTP.' 
                });
            }

            return res.status(400).json({ 
                success: false, 
                message: 'Invalid OTP. Please try again.' 
            });
        }

        // OTP is valid
        otpStorage.delete(email);
        res.json({ 
            success: true, 
            message: 'OTP verified successfully',
            email: email
        });
    } catch (error) {
        console.error('OTP verification error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Error verifying OTP. Please try again.',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

app.post('/reset-password', async (req, res) => {
    const { email, newPassword } = req.body;
    
    if (!email || !newPassword) {
        return res.status(400).json({ 
            success: false, 
            message: 'Email and new password are required' 
        });
    }

    try {
        // Check if user exists
        const [users] = await dbPromise.query('SELECT * FROM users WHERE email = ?', [email]);
        if (users.length === 0) {
            return res.status(404).json({ 
                success: false, 
                message: 'User not found' 
            });
        }

        // Hash the new password
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        // Update the password
        await dbPromise.query(
            'UPDATE users SET password = ? WHERE email = ?',
            [hashedPassword, email]
        );

        res.json({ 
            success: true, 
            message: 'Password reset successfully',
            email: email
        });
    } catch (error) {
        console.error('Password reset error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Error resetting password. Please try again.',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// ===================
// GLOBAL DB ERROR HANDLER
// ===================
db.on('error', (err) => {
    console.error('Database error:', err);
    if (err.code === 'PROTOCOL_CONNECTION_LOST') {
        db.connect((connectErr) => {
            if (connectErr) {
                console.error('Reconnection failed:', connectErr);
            } else {
                console.log('Successfully reconnected to database');
            }
        });
    }
});

// ===================
// CLASS ROUTES
// ===================

// Get total students in classkern
app.get('/class-students', (_req, res) => {
    db.query('SELECT COUNT(*) AS total FROM classkern', (error, results) => {
        if (error) return res.status(500).json({ error: 'Database query failed' });
        res.json({ total: results[0].total });
    });
});

// Get all classes
app.get('/get-classes', (req, res) => {
    db.query('SELECT * FROM classkern', (err, results) => {
        if (err) return res.status(500).json({ error: 'Failed to fetch classes', details: err.message });
        res.json(results);
    });
});

// Create a class
app.post('/add-class', (req, res) => {
    const { classname, classteacher, studentlimit } = req.body;
    if (!classname?.trim() || !classteacher?.trim() || !studentlimit) {
        return res.status(400).json({ error: 'All fields are required' });
    }
    const parsedStudentLimit = Number(studentlimit);
    const checkDuplicateQuery = 'SELECT * FROM classkern WHERE classname = ? AND classteacher = ?';
    db.query(checkDuplicateQuery, [classname.trim(), classteacher.trim()], (checkErr, checkResults) => {
        if (checkErr) return res.status(500).json({ error: 'Database error during duplicate check' });
        if (checkResults.length > 0) return res.status(409).json({ error: 'A class with this name and teacher already exists' });
        const query = 'INSERT INTO classkern (classname, classteacher, studentlimit) VALUES (?, ?, ?)';
        db.query(query, [classname.trim(), classteacher.trim(), parsedStudentLimit], (err, result) => {
            if (err) return res.status(500).json({ error: 'Database error during insert' });
            res.json({
                message: 'Class created successfully!',
                updatedClass: {
                    id: result.insertId,
                    classname,
                    classteacher,
                    studentlimit: parsedStudentLimit,
                }
            });
        });
    });
});

// Edit class
app.put('/edit-class/:id', (req, res) => {
    const { id } = req.params;
    const { classname, classteacher, studentlimit } = req.body;
    if (!id || isNaN(parseInt(id))) return res.status(400).json({ error: 'Invalid class ID' });
    const trimmedClassName = classname ? classname.trim() : '';
    if (!trimmedClassName) return res.status(400).json({ error: 'Class name is required' });
    if (trimmedClassName.length > 100) return res.status(400).json({ error: 'Class name is too long (max 100 characters)' });
    const trimmedClassTeacher = classteacher ? classteacher.trim() : '';
    if (!trimmedClassTeacher) return res.status(400).json({ error: 'Class teacher is required' });
    if (trimmedClassTeacher.length > 100) return res.status(400).json({ error: 'Teacher name is too long (max 100 characters)' });
    const parsedStudentLimit = parseInt(studentlimit);
    if (isNaN(parsedStudentLimit) || parsedStudentLimit < 1 || parsedStudentLimit > 1000) {
        return res.status(400).json({ error: 'Student limit must be a number between 1 and 1000' });
    }
    const duplicateCheckQuery = `
      SELECT classid FROM classkern 
      WHERE classname = ? AND classteacher = ? AND classid != ?`;
    db.query(duplicateCheckQuery, [trimmedClassName, trimmedClassTeacher, id], (dupErr, dupResults) => {
        if (dupErr) return res.status(500).json({ error: 'Error checking for duplicate classes', details: dupErr.message });
        if (dupResults.length > 0) return res.status(409).json({ error: 'A class with the same name and teacher already exists', duplicateClassId: dupResults[0].classid });
        const checkExistQuery = 'SELECT * FROM classkern WHERE classid = ?';
        db.query(checkExistQuery, [id], (checkErr, checkResults) => {
            if (checkErr) return res.status(500).json({ error: 'Error checking class existence', details: checkErr.message });
            if (checkResults.length === 0) return res.status(404).json({ error: 'Class not found' });
            const updateQuery = 'UPDATE classkern SET classname = ?, classteacher = ?, studentlimit = ? WHERE classid = ?';
            db.query(updateQuery, [trimmedClassName, trimmedClassTeacher, parsedStudentLimit, id], (err, result) => {
                if (err) return res.status(500).json({ error: 'Error updating data in the database', details: err.message });
                if (result.affectedRows === 0) return res.status(500).json({ error: 'Failed to update class' });
                res.json({
                    message: 'Class updated successfully!',
                    updatedClass: {
                        id,
                        classname: trimmedClassName,
                        classteacher: trimmedClassTeacher,
                        studentlimit: parsedStudentLimit
                    }
                });
            });
        });
    });
});

// Delete class
app.delete('/delete-class/:id', (req, res) => {
    const { id } = req.params;
    if (!id || isNaN(id)) return res.status(400).json({ error: 'Invalid class ID' });
    const query = 'DELETE FROM classkern WHERE classid = ?';
    db.query(query, [id], (err, result) => {
        if (err) return res.status(500).json({ error: 'Error deleting data from the database', details: err.message });
        if (result.affectedRows === 0) return res.status(404).json({ error: 'Class not found' });
        res.json({ message: 'Class deleted successfully!', deletedClassId: id });
    });
});


// Create classkern table if not exists
const createClasskernTableQuery = `
CREATE TABLE IF NOT EXISTS classkern (
  classid INT AUTO_INCREMENT PRIMARY KEY,
  classname VARCHAR(100) NOT NULL,
  classteacher VARCHAR(100) NOT NULL,
  studentlimit INT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)`;


db.query(createClasskernTableQuery, (err) => {
    if (err) console.error('Error creating classkern table:', err);
});


// ===================
// STUDENT ROUTES
// ===================

// Get total students in studentawt
app.get('/total-students', (_req, res) => {
    db.query('SELECT COUNT(*) AS total FROM studentawt', (error, results) => {
        if (error) return res.status(500).json({ error: 'Database query failed' });
        res.json({ total: results[0].total });
    });
});

// Get all students (with search)
app.get('/students', (req, res) => {
    const searchTerm = req.query.search ? `%${req.query.search}%` : '%';
    const sql = 'SELECT * FROM studentawt WHERE name LIKE ? OR email LIKE ?';
    db.query(sql, [searchTerm, searchTerm], (err, results) => {
        if (err) return res.status(500).json({ message: 'Invalid query: ' + err.message });
        res.json(results);
    });
});

// Get student by ID
app.get('/students/:id', (req, res) => {
    const id = req.params.id;
    const sql = 'SELECT * FROM studentawt WHERE id = ?';
    db.query(sql, [id], (error, results) => {
        if (error) return res.status(500).json({ message: 'Error fetching student' });
        if (results.length === 0) return res.status(404).json({ message: 'Student not found' });
        res.json(results[0]);
    });
});

// Create student
app.post('/students', (req, res) => {
    const { name, email, phone, address } = req.body;
    if (!name || !email || !phone || !address) {
        return res.status(400).json({ message: 'All fields are required' });
    }
    const sql = 'INSERT INTO studentawt (name, email, phone, address) VALUES (?, ?, ?, ?)';
    db.query(sql, [name, email, phone, address], (err, result) => {
        if (err) {
            if (err.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: 'The data already exists' });
            return res.status(500).json({ error: 'Error creating student' });
        }
        res.json({ message: 'Student created successfully', id: result.insertId });
    });
});

// Update student
app.put('/students/:id', (req, res) => {
    const id = req.params.id;
    const { name, email, phone, address } = req.body;
    if (!name || !email || !phone || !address) {
        return res.status(400).json({ message: 'All fields are required' });
    }
    const trimmedName = name.trim();
    const trimmedEmail = email.trim().toLowerCase();
    const trimmedPhone = phone.trim();
    const trimmedAddress = address.trim();
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(trimmedEmail)) {
        return res.status(400).json({ message: 'Invalid email format' });
    }
    const checkStudentQuery = 'SELECT * FROM studentawt WHERE id = ?';
    db.query(checkStudentQuery, [id], (checkErr, checkResults) => {
        if (checkErr) return res.status(500).json({ message: 'Error checking student existence' });
        if (checkResults.length === 0) return res.status(404).json({ message: 'Student not found' });
        const duplicateCheckQuery = `
          SELECT id, name, email, phone 
          FROM studentawt 
          WHERE (email = ? OR phone = ?) AND id != ?`;
        db.query(duplicateCheckQuery, [trimmedEmail, trimmedPhone, id], (dupErr, dupResults) => {
            if (dupErr) return res.status(500).json({ message: 'Error checking for duplicate students' });
            if (dupResults.length > 0) {
                const duplicateEntries = dupResults.map(entry => ({
                    id: entry.id,
                    name: entry.name,
                    conflictField: entry.email === trimmedEmail ? 'email' : 'phone'
                }));
                return res.status(409).json({
                    message: 'Duplicate student entry found',
                    duplicates: duplicateEntries
                });
            }
            const updateSql = 'UPDATE studentawt SET name = ?, email = ?, phone = ?, address = ? WHERE id = ?';
            db.query(updateSql, [trimmedName, trimmedEmail, trimmedPhone, trimmedAddress, id], (err, result) => {
                if (err) return res.status(500).json({ message: 'Error updating student' });
                if (result.affectedRows === 0) return res.status(404).json({ message: 'Student not found or no changes made' });
                res.json({
                    message: 'Student updated successfully',
                    updatedStudent: {
                        id,
                        name: trimmedName,
                        email: trimmedEmail,
                        phone: trimmedPhone,
                        address: trimmedAddress
                    }
                });
            });
        });
    });
});

// Delete student
app.delete('/students/:id', (req, res) => {
    const id = req.params.id;
    const sql = 'DELETE FROM studentawt WHERE id = ?';
    db.query(sql, [id], (err) => {
        if (err) return res.status(500).json({ message: 'Error deleting student' });
        res.json({ message: 'Student deleted successfully' });
    });
});


// Create studentawt table if not exists
const createStudentawtTableQuery = `
CREATE TABLE IF NOT EXISTS studentawt (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  email VARCHAR(100) NOT NULL,
  phone VARCHAR(20) NOT NULL,
  address VARCHAR(255) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)`;


db.query(createStudentawtTableQuery, (err) => {
    if (err) console.error('Error creating studentawt table:', err);
});


// ===================
// AUTH & USER ROUTES
// ===================


// Create users table if not exists
const createUserTableQuery = `
CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(50) UNIQUE NOT NULL,
  email VARCHAR(100) UNIQUE NOT NULL,
  password VARCHAR(255) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)`;

db.query(createUserTableQuery, (err) => {
    if (err) console.error('Error creating users table:', err);
});


// Get user details
app.get('/api/user-details', async (req, res) => {
    if (!req.session || !req.session.userId) {
        return res.status(401).json({ success: false, message: 'Unauthorized - Please log in' });
    }
    try {
        const userId = req.session.userId;
        if (!Number.isInteger(userId) || userId <= 0) {
            return res.status(400).json({ success: false, message: 'Invalid session data' });
        }
        const [rows] = await dbPromise.query('SELECT username FROM users WHERE id = ?', [userId]);
        if (rows.length === 0) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        res.json({ success: true, user: { username: rows[0].username } });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});



// ===================
// START SERVER
// ===================
const PORT = process.env.PORT || 5000;
app.listen(PORT, (err) => {
    if (err) {
        console.error('Failed to start server:', err.message);
    } else {
        console.log(`Server running on port ${PORT}`);
    }
});