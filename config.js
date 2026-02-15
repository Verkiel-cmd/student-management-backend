// config.js
// Load environment variables from .env file
import dotenv from 'dotenv';

dotenv.config();

const config = {
    GOOGLE_CLIENT_ID: process.env.GOOGLE_CLIENT_ID,
    SESSION_SECRET: process.env.SESSION_SECRET,
    DB_HOST: process.env.DB_HOST,       // Using MYSQLHOST from Render's environment
    DB_USER: process.env.DB_USER,       // Using MYSQLUSER from Render's environment
    DB_PASSWORD: process.env.DB_PASSWORD, // Using MYSQLPASSWORD from Render's environment
    DB_NAME: process.env.DB_NAME,
    NODE_ENV: process.env.NODE_ENV || 'development',
};

export default config;