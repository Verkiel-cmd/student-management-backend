import express from 'express';
import mysql from 'mysql2';
import cors from 'cors';

const app = express();

app.use((req, res, next) => {
  console.log(`Request URL: ${req.url}`);
  console.log(`Request Method: ${req.method}`);
  console.log(`Request Headers: ${JSON.stringify(req.headers)}`);
  next();
});

app.use(express.json());
app.use(cors({
  origin: 'http://localhost:5173',
  credentials: true
}));


const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'data_stu'
});

db.connect((err) => {
  if (err) {
    console.error('Database connection failed:', err.message);
    return;
  }
  console.log('Connected to the MySQL database');
});



//TOTAL STUDENTS
app.get('/total-students', (_req, res) => {
  console.log('Fetching total students...');
  const query = 'SELECT COUNT(*) AS total FROM studentawt';
  db.query(query, (error, results) => {
    if (error) {
      console.error('Database query failed:', error.message);
      return res.status(500).json({ error: 'Database query failed' });
    }
    res.json({ total: results[0].total });
  });
});



// GET STUDENTS
app.get('/students/:id', (req, res) => {
  const id = req.params.id;
  const sql = 'SELECT * FROM studentawt WHERE id = ?';
  console.log('Executing SQL query:', sql, 'with ID:', id);

  db.query(sql, [id], (error, results) => {
    if (error) {
      console.error('Fetch error:', error.message);
      return res.status(500).json({ message: 'Error fetching student' });
    }

    if (results.length === 0) {
      console.log(`No student found with ID: ${id}`);
      return res.status(404).json({ message: 'Student not found' });
    }
    console.log(`Student with ID: ${id} found:`, results[0]);
    res.json(results[0]);
  });
});








// Global error handler for database connection losses
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


// SEARCH Students
app.get('/students', (req, res) => {
  console.log('GET /students - Fetching students');
  const searchTerm = req.query.search ? `%${req.query.search}%` : '%';
  console.log('Search term:', searchTerm);
  const sql = 'SELECT * FROM studentawt WHERE name LIKE ? OR email LIKE ?';
  console.log('Executing SQL query:', sql, 'with search term:', searchTerm);

  db.query(sql, [searchTerm, searchTerm], (err, results) => {
    if (err) {
      console.error('Invalid query:', err.message);
      return res.status(500).json({ message: 'Invalid query: ' + err.message });
    }
    console.log('Number of students found:', results.length);

    if (results.length === 0) {
      console.log('No students found matching the search criteria');
    }
    res.json(results);
  });
});

// POST create student
app.post('/students', (req, res) => {
  console.log('POST /students - Creating a new student');
  const { name, email, phone, address } = req.body;
  console.log('Received data:', { name, email, phone, address });


  if (!name || !email || !phone || !address) {
    return res.status(400).json({ message: 'All fields are required' });
  }

  const sql = 'INSERT INTO studentawt (name, email, phone, address) VALUES (?, ?, ?, ?)';
  db.query(sql, [name, email, phone, address], (err, result) => {
    if (err) {
      if (err.code === 'ER_DUP_ENTRY') {
        console.error('Duplicate entry error:', err.message);
        return res.status(409).json({ error: 'The data already exists' });
      }
      console.error('Insert error:', err.message);
      return res.status(500).json({ error: 'Error creating student' });
    }
    console.log('Student created successfully, ID:', result.insertId);
    res.json({ message: 'Student created successfully', id: result.insertId });
  });
});



// PUT update student
app.put('/students/:id', (req, res) => {
  console.log(`PUT /students/${req.params.id} - Updating student`);
  const id = req.params.id;
  const { name, email, phone, address } = req.body;
  console.log('Received data:', { name, email, phone, address });

  if (!name || !email || !phone || !address) {
    return res.status(400).json({ message: 'All fields are required' });
  }

  // Trim 
  const trimmedName = name.trim();
  const trimmedEmail = email.trim().toLowerCase();
  const trimmedPhone = phone.trim();
  const trimmedAddress = address.trim();

  // Validate email format
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(trimmedEmail)) {
    return res.status(400).json({ message: 'Invalid email format' });
  }

  // First, check if the student exists
  const checkStudentQuery = 'SELECT * FROM studentawt WHERE id = ?';
  db.query(checkStudentQuery, [id], (checkErr, checkResults) => {
    if (checkErr) {
      console.error('Error checking student existence:', checkErr);
      return res.status(500).json({ message: 'Error checking student existence' });
    }

    if (checkResults.length === 0) {
      return res.status(404).json({ message: 'Student not found' });
    }

    // Check for duplicate students (by email or phone, excluding current student)
    const duplicateCheckQuery = `
      SELECT id, name, email, phone 
      FROM studentawt 
      WHERE (email = ? OR phone = ?) AND id != ?`;

    db.query(duplicateCheckQuery, [trimmedEmail, trimmedPhone, id], (dupErr, dupResults) => {
      if (dupErr) {
        console.error('Duplicate check error:', dupErr.message);
        return res.status(500).json({ message: 'Error checking for duplicate students' });
      }

      // Check if duplicate exists
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

      // If no duplicates, continue update
      const updateSql = 'UPDATE studentawt SET name = ?, email = ?, phone = ?, address = ? WHERE id = ?';
      console.log('Executing SQL query:', updateSql);

      db.query(updateSql, [trimmedName, trimmedEmail, trimmedPhone, trimmedAddress, id], (err, result) => {
        if (err) {
          console.error('Update error:', err.message);
          return res.status(500).json({ message: 'Error updating student' });
        }

        // Verify that a row was actually updated
        if (result.affectedRows === 0) {
          return res.status(404).json({ message: 'Student not found or no changes made' });
        }

        console.log(`Student with ID: ${id} updated successfully`);
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



// DELETE student
app.delete('/students/:id', (req, res) => {
  console.log(`DELETE /students/${req.params.id} - Deleting student`);
  const id = req.params.id;
  const sql = 'DELETE FROM studentawt WHERE id = ?';

  db.query(sql, [id], (err) => {
    if (err) {
      console.error('Delete error:', err.message);
      return res.status(500).json({ message: 'Error deleting student' });
    }
    console.log(`Student with ID: ${id} deleted successfully`);
    res.json({ message: 'Student deleted successfully' });
  });
});


// Root route
app.get('/', (req, res) => {
  res.send('Welcome to the Student Management API!');
});

// Start the server
app.listen(3001, (err) => {
  if (err) {
    console.error('Failed to start server:', err.message);
  } else {
    console.log(`Server running on http://localhost:3001`);
  }
});
