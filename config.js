// config.js
import dotenv from 'dotenv';

// Load environment variables from .env file
dotenv.config();

const config = {
    GOOGLE_CLIENT_ID: '824956744352-a4sj5egukjh1csk8galsalp6v4i73gbq.apps.googleusercontent.com',
    SESSION_SECRET: 'y@9jLx9!*A4k!@Sg7b2Q$2uH9v7C4e5H',
    DB_HOST: process.env.MYSQLHOST,       // Using MYSQLHOST from Render's environment
    DB_USER: process.env.MYSQLUSER,       // Using MYSQLUSER from Render's environment
    DB_PASSWORD: process.env.MYSQLPASSWORD, // Using MYSQLPASSWORD from Render's environment
    DB_NAME: process.env.MYSQL_DATABASE,
};

export default config;