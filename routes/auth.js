const express = require('express');
const db = require('../db');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { generateOTP, sendOTPEmail } = require('../emailService');
require('dotenv').config();

const router = express.Router();
const saltRounds = 10;

// In-memory storage for OTPs (in production, use Redis or database)
const otpStorage = new Map();

// Helper function to determine if input is email or phone
const isEmail = (input) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(input);
};

// User Signup
router.post('/signup', (req, res) => {
  const { phone, fullname, email, password, confirmPassword } = req.body;

  if (!phone || !fullname || !email || !password || !confirmPassword) {
    return res.status(400).json({ error: 'Phone, fullname, email, password, and confirm password are required.' });
  }
  
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ error: 'Please enter a valid email address.' });
  }
  
  if (password !== confirmPassword) {
    return res.status(400).json({ error: 'Passwords do not match.' });
  }

  const checkQuery = 'SELECT idaccount FROM account WHERE phone = ?';
  db.query(checkQuery, [phone], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'Database error' });
    }
    if (results.length > 0) {
      return res.status(400).json({ error: 'A user with this phone already exists.' });
    }

    const checkEmailQuery = 'SELECT idaccount FROM account WHERE email = ?';
    db.query(checkEmailQuery, [email], (emailErr, emailResults) => {
      if (emailErr) {
        console.error(emailErr);
        return res.status(500).json({ error: 'Database error' });
      }
      if (emailResults.length > 0) {
        return res.status(400).json({ error: 'A user with this email already exists.' });
      }

      bcrypt.hash(password, saltRounds, (hashErr, hashedPassword) => {
        if (hashErr) {
          console.error(hashErr);
          return res.status(500).json({ error: 'Error processing password' });
        }

        const insertQuery = 'INSERT INTO account (phone, fullname, email, password) VALUES (?, ?, ?, ?)';
        db.query(insertQuery, [phone, fullname, email, hashedPassword], (insertErr, result) => {
          if (insertErr) {
            console.error(insertErr);
            return res.status(500).json({ error: 'Database error' });
          }
          res.status(201).json({ message: 'User created successfully' });
        });
      });
    });
  });
});

// Updated User Login - supports both email and phone
router.post('/login', (req, res) => {
  const { emailOrPhone, password } = req.body;

  if (!emailOrPhone || !password) {
    return res.status(400).json({ error: 'Email/phone and password are required.' });
  }

  const isEmailInput = isEmail(emailOrPhone);
  const query = isEmailInput 
    ? 'SELECT * FROM account WHERE email = ?'
    : 'SELECT * FROM account WHERE phone = ?';

  db.query(query, [emailOrPhone], (err, results) => {
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

      const token = jwt.sign(
        { 
          idaccount: user.idaccount, 
          phone: user.phone,
          email: user.email,
          role: user.role || null
        },
        process.env.JWT_SECRET || 'defaultSecretKey',
        { expiresIn: '1h' }
      );

      res.cookie('access_token', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'Strict'
      });

      res.json({ 
        message: 'Login successful',
        token: token,
        userRole: user.role
      });
    });
  });
});

// Send OTP for password reset
router.post('/send-reset-otp', async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: 'Email is required.' });
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ error: 'Please enter a valid email address.' });
  }

  // Check if user exists
  const query = 'SELECT * FROM account WHERE email = ?';
  db.query(query, [email], async (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'Database error' });
    }
    if (results.length === 0) {
      return res.status(404).json({ error: 'No account found with this email address.' });
    }

    const user = results[0];
    const otp = generateOTP();
    
    // Store OTP with expiration (10 minutes)
    const otpData = {
      otp: otp,
      email: email,
      timestamp: Date.now(),
      expiresAt: Date.now() + 10 * 60 * 1000 // 10 minutes
    };
    otpStorage.set(email, otpData);

    // Send OTP via email
    try {
      const emailResult = await sendOTPEmail(email, otp, user.fullname);
      if (emailResult.success) {
        res.json({ 
          message: 'Mã xác thực đã được gửi đến email của bạn',
          success: true 
        });
      } else {
        console.error('Email sending failed:', emailResult.error);
        res.status(500).json({ error: 'Failed to send verification code. Please try again.' });
      }
    } catch (error) {
      console.error('Error sending OTP email:', error);
      res.status(500).json({ error: 'Failed to send verification code. Please try again.' });
    }
  });
});

// Get user profile (protected route)
const authenticateToken = (req, res, next) => {
  // Try to get token from cookie first (for server-side requests)
  let token = req.cookies.access_token;
  
  // If no cookie token, try Authorization header (for client-side requests)
  if (!token) {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.substring(7); // Remove 'Bearer ' prefix
    }
  }
  
  if (!token) {
    return res.status(401).json({ error: 'Not authenticated.' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'defaultSecretKey', (err, decoded) => {
    if (err) {
      return res.status(401).json({ error: 'Invalid token.' });
    }
    req.user = decoded; // Store decoded user info for use in route handlers
    next();
  });
};

// Update your profile route to use the middleware
router.get('/profile', authenticateToken, (req, res) => {
  const userId = req.user.idaccount; // Get from decoded token
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

// Update your profile update route
router.put('/profile', authenticateToken, (req, res) => {
  const userId = req.user.idaccount; // Get from decoded token
  const { fullname, email, phone } = req.body;

  if (!fullname || !email || !phone) {
    return res.status(400).json({ error: 'Fullname, email, and phone are required.' });
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ error: 'Please enter a valid email address.' });
  }

  const checkEmailQuery = 'SELECT idaccount FROM account WHERE email = ? AND idaccount != ?';
  db.query(checkEmailQuery, [email, userId], (emailErr, emailResults) => {
    if (emailErr) {
      console.error(emailErr);
      return res.status(500).json({ error: 'Database error checking email.' });
    }
    if (emailResults.length > 0) {
      return res.status(400).json({ error: 'This email is already in use by another account.' });
    }

    const checkPhoneQuery = 'SELECT idaccount FROM account WHERE phone = ? AND idaccount != ?';
    db.query(checkPhoneQuery, [phone, userId], (phoneErr, phoneResults) => {
      if (phoneErr) {
        console.error(phoneErr);
        return res.status(500).json({ error: 'Database error checking phone.' });
      }
      if (phoneResults.length > 0) {
        return res.status(400).json({ error: 'This phone number is already in use by another account.' });
      }

      const updateQuery = 'UPDATE account SET fullname = ?, email = ?, phone = ? WHERE idaccount = ?';
      db.query(updateQuery, [fullname, email, phone, userId], (updateErr, result) => {
        if (updateErr) {
          console.error(updateErr);
          return res.status(500).json({ error: 'Database error updating profile.' });
        }
        if (result.affectedRows === 0) {
          return res.status(404).json({ error: 'User not found.' });
        }
        res.json({ 
          message: 'Profile updated successfully.',
          user: { fullname, email, phone }
        });
      });
    });
  });
});

// Update change password route
router.put('/change-password', authenticateToken, (req, res) => {
  const userId = req.user.idaccount;
  const { currentPassword, newPassword } = req.body;

  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: 'Current password and new password are required.' });
  }

  if (newPassword.length < 8) {
    return res.status(400).json({ error: 'New password must be at least 8 characters.' });
  }

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
    bcrypt.compare(currentPassword, user.password, (compErr, isMatch) => {
      if (compErr) {
        console.error(compErr);
        return res.status(500).json({ error: 'Error comparing password.' });
      }
      if (!isMatch) {
        return res.status(400).json({ error: 'Current password is incorrect.' });
      }

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

// Updated reset password to use OTP verification
router.post("/reset-password", (req, res) => {
  const { emailOrPhone, code, newPassword } = req.body;

  if (!emailOrPhone || !code || !newPassword) {
    return res.status(400).json({ error: "All fields are required." });
  }
  if (newPassword.length < 8) {
    return res.status(400).json({ error: "New password must be at least 8 characters." });
  }

  // Check if it's an email (for OTP verification)
  const isEmailInput = isEmail(emailOrPhone);
  
  if (isEmailInput) {
    // Verify OTP for email
    const storedOtpData = otpStorage.get(emailOrPhone);
    if (!storedOtpData) {
      return res.status(400).json({ error: "No verification code found. Please request a new code." });
    }
    
    if (Date.now() > storedOtpData.expiresAt) {
      otpStorage.delete(emailOrPhone);
      return res.status(400).json({ error: "Verification code has expired. Please request a new code." });
    }
    
    if (storedOtpData.otp !== code) {
      return res.status(400).json({ error: "Invalid verification code." });
    }
    
    // OTP is valid, remove it from storage
    otpStorage.delete(emailOrPhone);
  } else {
    // For phone numbers, keep the hardcoded verification for backward compatibility
    if (code !== "131313") {
      return res.status(400).json({ error: "Invalid verification code." });
    }
  }

  // Find user and update password
  const query = isEmailInput 
    ? "SELECT * FROM account WHERE email = ?"
    : "SELECT * FROM account WHERE phone = ?";

  db.query(query, [emailOrPhone], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: "Database error." });
    }
    if (results.length === 0) {
      return res.status(404).json({ error: "User not found." });
    }

    const user = results[0];
    bcrypt.hash(newPassword, saltRounds, (hashErr, hashedPassword) => {
      if (hashErr) {
        console.error(hashErr);
        return res.status(500).json({ error: "Error processing new password." });
      }

      const updateQuery = "UPDATE account SET password = ? WHERE idaccount = ?";
      db.query(updateQuery, [hashedPassword, user.idaccount], (updateErr, updateResult) => {
        if (updateErr) {
          console.error(updateErr);
          return res.status(500).json({ error: "Database error updating password." });
        }
        res.json({ message: "Password reset successfully." });
      });
    });
  });
});

// Clean up expired OTPs periodically (run this with a cron job in production)
setInterval(() => {
  const now = Date.now();
  for (const [email, otpData] of otpStorage.entries()) {
    if (now > otpData.expiresAt) {
      otpStorage.delete(email);
    }
  }
}, 5 * 60 * 1000); // Clean up every 5 minutes

module.exports = router;