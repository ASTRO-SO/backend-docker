const express = require('express');
const db = require('../db');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const router = express.Router();
const saltRounds = 10; // Adjust for a balance between speed and security

// User Signup
router.post('/signup', (req, res) => {
  const { phone, fullname, email, password, confirmPassword } = req.body;

  // Basic input validation
  if (!phone || !fullname || !password || !confirmPassword) {
    return res.status(400).json({ error: 'Phone, fullname, password, and confirm password are required.' });
  }
  if (password !== confirmPassword) {
    return res.status(400).json({ error: 'Passwords do not match.' });
  }

  // Check if a user with this phone already exists
  const checkQuery = 'SELECT idaccount FROM account WHERE phone = ?';
  db.query(checkQuery, [phone], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'Database error' });
    }
    if (results.length > 0) {
      return res.status(400).json({ error: 'A user with this phone already exists.' });
    }

    // Hash the password
    bcrypt.hash(password, saltRounds, (hashErr, hashedPassword) => {
      if (hashErr) {
        console.error(hashErr);
        return res.status(500).json({ error: 'Error processing password' });
      }

      const insertQuery = 'INSERT INTO account (phone, fullname, email, password) VALUES (?, ?, ?, ?)';
      db.query(insertQuery, [phone, fullname, email || null, hashedPassword], (insertErr, result) => {
        if (insertErr) {
          console.error(insertErr);
          return res.status(500).json({ error: 'Database error' });
        }
        res.status(201).json({ message: 'User created successfully' });
      });
    });
  });
});

// User Login
router.post('/login', (req, res) => {
  const { phone, password } = req.body;

  if (!phone || !password) {
    return res.status(400).json({ error: 'Phone and password are required.' });
  }

  const query = 'SELECT * FROM account WHERE phone = ?';
  db.query(query, [phone], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'Database error' });
    }
    if (results.length === 0) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const user = results[0];
    bcrypt.compare(password, user.password, (compErr, isMatch) => {
      if (compErr) {
        console.error(compErr);
        return res.status(500).json({ error: 'Error comparing password' });
      }
      if (!isMatch) {
        return res.status(400).json({ error: 'Invalid credentials' });
      }

      // Create a JWT token carrying minimal user information including role
      const token = jwt.sign(
        { 
          idaccount: user.idaccount, 
          phone: user.phone,
          role: user.role || null // Include role in the token
        },
        process.env.JWT_SECRET || 'defaultSecretKey',
        { expiresIn: '1h' }
      );

      // Store token in an HTTP-only cookie
      res.cookie('access_token', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production', // ensures HTTPS in production
        sameSite: 'Strict'
      });

      // Send token and role in response for frontend storage
      res.json({ 
        message: 'Login successful',
        token: token,
        userRole: user.role // Send role to the client
      });
    });
  });
});

// Get user profile (protected route)
router.get('/profile', (req, res) => {
  // Access token should be stored in the cookie 'access_token'
  const token = req.cookies.access_token;
  if (!token) {
    return res.status(401).json({ error: 'Not authenticated.' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'defaultSecretKey', (err, decoded) => {
    if (err) {
      return res.status(401).json({ error: 'Invalid token.' });
    }

    // Use the decoded token to fetch the user's data
    const userId = decoded.idaccount;
    const profileQuery = 'SELECT idaccount, phone, fullname, email FROM account WHERE idaccount = ?';
    db.query(profileQuery, [userId], (err, results) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'Database error.' });
      }
      if (results.length === 0) {
        return res.status(404).json({ error: 'User not found.' });
      }
      res.json(results[0]);
    });
  });
});

// Change password (protected route)
router.put('/change-password', (req, res) => {
  // Access token should be stored in the cookie 'access_token'
  const token = req.cookies.access_token;
  if (!token) {
    return res.status(401).json({ error: 'Not authenticated.' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'defaultSecretKey', (err, decoded) => {
    if (err) {
      return res.status(401).json({ error: 'Invalid token.' });
    }

    const userId = decoded.idaccount;
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'Current password and new password are required.' });
    }

    if (newPassword.length < 8) {
      return res.status(400).json({ error: 'New password must be at least 8 characters.' });
    }

    // Fetch user data to compare current password
    const query = 'SELECT * FROM account WHERE idaccount = ?';
    db.query(query, [userId], (err, results) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'Database error.' });
      }
      if (results.length === 0) {
        return res.status(404).json({ error: 'User not found.' });
      }

      const user = results[0];
      // Compare the provided current password with the stored hashed password
      bcrypt.compare(currentPassword, user.password, (compErr, isMatch) => {
        if (compErr) {
          console.error(compErr);
          return res.status(500).json({ error: 'Error comparing password.' });
        }
        if (!isMatch) {
          return res.status(400).json({ error: 'Current password is incorrect.' });
        }

        // Hash the new password
        bcrypt.hash(newPassword, saltRounds, (hashErr, hashedPassword) => {
          if (hashErr) {
            console.error(hashErr);
            return res.status(500).json({ error: 'Error processing new password.' });
          }

          const updateQuery = 'UPDATE account SET password = ? WHERE idaccount = ?';
          db.query(updateQuery, [hashedPassword, userId], (updateErr, result) => {
            if (updateErr) {
              console.error(updateErr);
              return res.status(500).json({ error: 'Database error updating password.' });
            }
            res.json({ message: 'Password updated successfully.' });
          });
        });
      });
    });
  });
});

router.post("/reset-password", (req, res) => {
  const { phone, code, newPassword } = req.body;

  // Basic validation check
  if (!phone || !code || !newPassword) {
    return res.status(400).json({ error: "All fields are required." });
  }
  if (newPassword.length < 8) {
    return res.status(400).json({ error: "New password must be at least 8 characters." });
  }

  // In production, compare against a stored verification code.
  // Here, we assume that the valid code is "131313" for testing.
  if (code !== "131313") {
    return res.status(400).json({ error: "Invalid verification code." });
  }

  // Look up the user by phone number.
  const query = "SELECT * FROM account WHERE phone = ?";
  db.query(query, [phone], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: "Database error." });
    }
    if (results.length === 0) {
      return res.status(404).json({ error: "User not found." });
    }

    // Hash the new password.
    bcrypt.hash(newPassword, saltRounds, (hashErr, hashedPassword) => {
      if (hashErr) {
        console.error(hashErr);
        return res.status(500).json({ error: "Error processing new password." });
      }

      // Update the password in the database.
      const updateQuery = "UPDATE account SET password = ? WHERE phone = ?";
      db.query(updateQuery, [hashedPassword, phone], (updateErr, updateResult) => {
        if (updateErr) {
          console.error(updateErr);
          return res.status(500).json({ error: "Database error updating password." });
        }
        res.json({ message: "Password reset successfully." });
      });
    });
  });
});



module.exports = router;