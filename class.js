import express from 'express';
import mysql from 'mysql2';
import cors from 'cors';
const app = express();
import dotenv from 'dotenv';
dotenv.config();

app.use((req, res, next) => {
    console.log(`Request URL: ${req.url}`);
    console.log(`Request Method: ${req.method}`);
    console.log(`Request Headers: ${JSON.stringify(req.headers)}`);
    next();
});


app.use(cors({
    origin: 'https://student-management-frontend-xhec.vercel.app', // Replace with your frontend's URL
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

db.connect((err) => {
    if (err) {
        console.error('Database connection failed:', err.message);
        return;
    }
    console.log('Connected to the MySQL database');
});




//TOTAL STUDENTS
app.get('https://student-management-backend-a2q4.onrender.com/class-students', (_req, res) => {
    console.log('Fetching total students...');
    const query = 'SELECT COUNT(*) AS total FROM classkern';
    db.query(query, (error, results) => {
        if (error) {
            console.error('Database query failed:', error.message);
            return res.status(500).json({ error: 'Database query failed' });
        }
        res.json({ total: results[0].total });
    });
});









// Get all classes endpoint
app.get('https://student-management-backend-a2q4.onrender.com/get-classes', (req, res) => {
    console.log('Received request for /get-classes');

    // Removed the ORDER BY clause that was causing the error
    db.query('SELECT * FROM classkern', (err, results) => {
        if (err) {
            console.error('Database query error:', err);
            return res.status(500).json({
                error: 'Failed to fetch classes',
                details: err.message
            });
        }
        console.log('Successfully fetched classes:', results);
        res.json(results);
    });
});



// Global error handler for database 
db.on('error', (err) => {
    console.error('Database error:', err);
    if (err.code === 'PROTOCOL_CONNECTION_LOST') {
        console.error('Database connection was closed. Attempting to reconnect...');
        db.connect((connectErr) => {
            if (connectErr) {
                console.error('Reconnection failed:', connectErr);
            } else {
                console.log('Successfully reconnected to database');
            }
        });
    }
});



// Create a class
app.post('https://student-management-backend-a2q4.onrender.com/add-class', (req, res) => {
    const { classname, classteacher, studentlimit } = req.body;

    // Input validation
    if (!classname?.trim() || !classteacher?.trim() || !studentlimit) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    const parsedStudentLimit = Number(studentlimit);


    const checkDuplicateQuery = 'SELECT * FROM classkern WHERE classname = ? AND classteacher = ?';
    db.query(checkDuplicateQuery, [classname.trim(), classteacher.trim()], (checkErr, checkResults) => {
        if (checkErr) {
            console.error('Database error during duplicate check:', checkErr);
            return res.status(500).json({ error: 'Database error during duplicate check' });
        }


        if (checkResults.length > 0) {
            console.error('Duplicate entry error: Class already exists');
            return res.status(409).json({ error: 'A class with this name and teacher already exists' });
        }


        const query = 'INSERT INTO classkern (classname, classteacher, studentlimit) VALUES (?, ?, ?)';
        db.query(query, [classname.trim(), classteacher.trim(), parsedStudentLimit], (err, result) => {
            if (err) {
                console.error('Database error during insert:', err);
                return res.status(500).json({ error: 'Database error during insert' });
            }

            const newClass = {
                id: result.insertId,
                classname,
                classteacher,
                studentlimit: parsedStudentLimit,
            };

            console.log('Class created successfully:', newClass);

            res.json({
                message: 'Class created successfully!',
                updatedClass: newClass,
            });
        });
    });
});


// Edit class
app.put('https://student-management-backend-a2q4.onrender.com/edit-class/:id', (req, res) => {
    const { id } = req.params;
    console.log('Received edit request for class ID:', id);

    const { classname, classteacher, studentlimit } = req.body;
    console.log('Request body:', req.body);

    try {
        console.log('Validating ID:', id);
        if (!id || isNaN(parseInt(id))) {
            console.error('Invalid class ID provided:', id);
            return res.status(400).json({ error: 'Invalid class ID' });
        }
        console.log('Class ID is valid:', id);


        const trimmedClassName = classname ? classname.trim() : '';

        console.log('Validating classname:', classname);
        if (!trimmedClassName) {
            return res.status(400).json({ error: 'Class name is required' });
        }
        if (trimmedClassName.length > 100) {
            return res.status(400).json({ error: 'Class name is too long (max 100 characters)' });
        }
        console.log('Class name is valid:', trimmedClassName);

        const trimmedClassTeacher = classteacher ? classteacher.trim() : '';

        console.log('Validating class teacher name:', classteacher);
        if (!trimmedClassTeacher) {
            return res.status(400).json({ error: 'Class teacher is required' });
        }
        if (trimmedClassTeacher.length > 100) {
            return res.status(400).json({ error: 'Teacher name is too long (max 100 characters)' });
        }
        console.log('Class teacher name is valid:', trimmedClassTeacher);


        const parsedStudentLimit = parseInt(studentlimit);

        console.log('Validating student limit:', studentlimit);
        if (isNaN(parsedStudentLimit) || parsedStudentLimit < 1 || parsedStudentLimit > 1000) {
            return res.status(400).json({ error: 'Student limit must be a number between 1 and 1000' });
        }
        console.log('Student limit is valid:', parsedStudentLimit);


        const duplicateCheckQuery = `
          SELECT classid FROM classkern 
          WHERE classname = ? AND classteacher = ? AND classid != ?`;

        db.query(duplicateCheckQuery, [trimmedClassName, trimmedClassTeacher, id], (dupErr, dupResults) => {
            if (dupErr) {
                console.error('Error checking for duplicate classes:', dupErr);
                return res.status(500).json({
                    error: 'Error checking for duplicate classes',
                    details: dupErr.message
                });
            }


            if (dupResults.length > 0) {
                return res.status(409).json({
                    error: 'A class with the same name and teacher already exists',
                    duplicateClassId: dupResults[0].classid
                });
            }


            const checkExistQuery = 'SELECT * FROM classkern WHERE classid = ?';
            db.query(checkExistQuery, [id], (checkErr, checkResults) => {
                if (checkErr) {
                    console.error('Error checking class existence:', checkErr);
                    return res.status(500).json({
                        error: 'Error checking class existence',
                        details: checkErr.message
                    });
                }

                if (checkResults.length === 0) {
                    return res.status(404).json({ error: 'Class not found' });
                }

                const updateQuery = 'UPDATE classkern SET classname = ?, classteacher = ?, studentlimit = ? WHERE classid = ?';
                db.query(updateQuery, [trimmedClassName, trimmedClassTeacher, parsedStudentLimit, id], (err, result) => {
                    if (err) {
                        console.error('Database error during update:', err);
                        return res.status(500).json({
                            error: 'Error updating data in the database',
                            details: err.message
                        });
                    }


                    if (result.affectedRows === 0) {
                        console.log('No rows were updated - unexpected error');
                        return res.status(500).json({ error: 'Failed to update class' });
                    }

                    console.log('Update successful:', result);
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

    } catch (error) {
        console.error('Unexpected error in edit-class route:', error);
        res.status(500).json({
            error: 'An unexpected error occurred',
            details: error.message
        });
    }
});



// Delete class
app.delete('https://student-management-backend-a2q4.onrender.com/delete-class/:id', (req, res) => {
    console.log('Received delete request for class:', req.params.id);

    const { id } = req.params;

    if (!id || isNaN(id)) {
        return res.status(400).json({ error: 'Invalid class ID' });
    }


    const query = 'DELETE FROM classkern WHERE classid = ?';
    db.query(query, [id], (err, result) => {
        if (err) {
            console.error('Database error during delete:', err);
            return res.status(500).json({
                error: 'Error deleting data from the database',
                details: err.message
            });
        }

        if (result.affectedRows === 0) {
            console.log('No rows were deleted - class might not exist');
            return res.status(404).json({ error: 'Class not found' });
        }

        console.log('Delete successful:', result);
        res.json({
            message: 'Class deleted successfully!',
            deletedClassId: id
        });
    });
});




// Start the server
app.listen(5000, (err) => {
    if (err) {
        console.error('Failed to start server:', err.message);
    } else {
        console.log(`Server running on http://localhost:5000`);
    }
});
