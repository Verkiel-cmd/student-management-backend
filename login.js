import express from 'express';
import mysql from 'mysql2';
import cors from 'cors';
import bcrypt from 'bcrypt';
import session from 'express-session';
import MySQLSession from 'express-mysql-session';
const MySQLStore = MySQLSession(session);
import config from './config.js';
import { OAuth2Client } from 'google-auth-library';

const app = express();

// Database session store
const sessionStore = new MySQLStore({
    host: config.DB_HOST,
    user: config.DB_USER,
    password: config.DB_PASSWORD,
    database: config.DB_NAME,
    clearExpired: true,
    checkExpirationInterval: 900000, // 15 minutes
    expiration: 86400000, // 1 day
});

// Proper session setup
app.use(session({
    secret: config.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: sessionStore,
    cookie: {
        secure: false, // Set to true if using HTTPS
        httpOnly: true,
        maxAge: 1000 * 60 * 60 * 24 // 1 day
    }
}));



app.use((req, res, next) => {
    console.log(`Request URL: ${req.url}`);
    console.log(`Request Method: ${req.method}`);
    console.log(`Session:`, req.session);
    console.log(`Request Headers: ${JSON.stringify(req.headers)}`);
    next();
});

app.use(express.json());

app.use(cors({
    origin: 'http://localhost:5173',
    credentials: true
}));



const db = mysql.createConnection({
    host: config.DB_HOST,        // MYSQLHOST from Render's environment
    user: config.DB_USER,        // MYSQLUSER from Render's environment
    password: config.DB_PASSWORD, // MYSQLPASSWORD from Render's environment
    database: config.DB_NAME,     // MYSQL_DATABASE from Render's environment
    port: process.env.MYSQLPORT || 3306, // Optional: use MYSQLPORT if you have a custom port
});

db.connect(err => {
    if (err) {
        console.error('Error connecting to database:', err);
        return;
    }
    console.log('Connected to MySQL database');
});


const dbPromise = db.promise();



const createUserTableQuery = `
CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(50) UNIQUE NOT NULL,
  email VARCHAR(100) UNIQUE NOT NULL,
  password VARCHAR(255) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)`;

db.query(createUserTableQuery, (err) => {
    if (err) {
        console.error('Error creating users table:', err);
    }
});

await dbPromise.query(createUserTableQuery);


app.get('/api/user-details', async (req, res) => {

    if (process.env.NODE_ENV === 'development') {
        console.log('Session:', req.session);
    }


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

        res.json({
            success: true,
            user: {
                username: rows[0].username,
            }
        });

    } catch (error) {
        console.error('Error fetching user details:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});



// Debugging session on every request
app.use((req, res, next) => {
    console.log('Session Data:', req.session);
    next();
});

app.use((req, res, next) => {
    if (!req.session.user && !["/login", "/register", "/google-login", "/check-username", "/forgot-password", "/reset-password"].includes(req.path)) {
        return res.status(401).json({ error: "Unauthorized - Please login" });
    }
    next();
});


// Registration Route
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


        const [result] = await db.promise().query(
            'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
            [username, email, hashedPassword]
        );

        req.session.userId = result.insertId;
        req.session.username = username;

        // Force session save
        req.session.save(err => {
            if (err) {
                console.error('Session save error:', err);
                return res.status(500).json({ success: false, message: 'Session error' });
            }
            res.status(201).json({
                success: true,
                message: 'User registered successfully',
                userId: result.insertId,
                username: username,
                email: email,
                redirectUrl: '/Frontlog'
            });
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error. Please try again later.'
        });
    }
});





// Login Route
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {

        const result = await dbPromise.query(
            'SELECT * FROM users WHERE email = ?',
            [email]
        );
        const users = result[0]; // Extract the first element


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
        req.session.username = user.username; // Add this line to store the username in the session

        // Force session save
        req.session.save(err => {
            if (err) {
                console.error('Session save error:', err);
                return res.status(500).json({ success: false, message: 'Session error' });
            }
            res.json({
                success: true,
                message: 'Login successful',
                userId: user.id,
                username: user.username,
                redirectUrl: '/ListStud'
            });
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error. Please try again later.'
        });
    }
});

// Logout Route
app.post("/logout", (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ error: "Logout failed" });
        }
        res.clearCookie("user_sid");
        res.json({ message: "Logout successful" });
    });
});

// Google Sign-In route
app.post('/google-login', async (req, res) => {
    const { token } = req.body;

    console.log('Received token:', token);

    try {
        const client = new OAuth2Client('824956744352-a4sj5egukjh1csk8galsalp6v4i73gbq.apps.googleusercontent.com');
        const ticket = await client.verifyIdToken({
            idToken: token,
            audience: '824956744352-a4sj5egukjh1csk8galsalp6v4i73gbq.apps.googleusercontent.com', // Same Client ID here
        });
        const payload = ticket.getPayload();
        const email = payload.email;

        db.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
            if (err) return res.status(500).send({ message: 'Database error' });

            if (results.length === 0) {

                db.query('INSERT INTO users (email, password) VALUES (?, ?)', [email, ''], (insertErr) => {
                    if (insertErr) return res.status(500).send({ message: 'Database error' });
                    return res.status(200).send({ success: true, message: 'Google login successful' });
                });
            } else {
                return res.status(200).send({ success: true, message: 'Google login successful' });
            }
        });
    } catch (error) {
        return res.status(401).send({ message: 'Invalid Google token' });
    }
});

app.get('/session', (req, res) => {
    if (req.session.username) {
        res.json({ username: req.session.username });
    } else {
        res.status(401).json({ message: 'Not logged in' });
    }
});


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
        console.error('Error checking username:', error);
        res.status(500).json({ exists: false, message: 'Server error' });
    }
});



//Start the server
app.listen(8080, (err) => {
    if (err) {
        console.error('Failed to start server:', err.message);
    } else {
        console.log(`Server running on http://localhost:8080`);
    }
});