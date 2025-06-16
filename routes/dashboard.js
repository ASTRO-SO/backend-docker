// backend/routes/users.js or similar
const express = require("express");
const db = require("../db"); // MySQL pool or connection
const router = express.Router();

// GET all users
router.get("/", (req, res) => {
  const query = "SELECT idaccount, phone, fullname, email, role FROM account WHERE idaccount IS NOT NULL ORDER BY idaccount";
  
  db.query(query, (err, results) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ error: "Failed to retrieve users." });
    }
    
    res.status(200).json(results);
  });
});

// GET single user by ID
router.get("/:id", (req, res) => {
  const { id } = req.params;
  const query = "SELECT idaccount, phone, fullname, email, role FROM account WHERE idaccount = ?";
  
  db.query(query, [id], (err, results) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ error: "Failed to retrieve user." });
    }
    
    if (results.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }
    
    res.status(200).json(results[0]);
  });
});

// POST create new user
router.post("/", (req, res) => {
  const { phone, fullname, password, email, role } = req.body;
  
  // Basic validation
  if (!phone || !fullname || !password) {
    return res.status(400).json({ error: "Phone, fullname, and password are required" });
  }
  
  const query = "INSERT INTO account (phone, fullname, password, email, role) VALUES (?, ?, ?, ?, ?)";
  
  db.query(query, [phone, fullname, password, email || null, role || 'user'], (err, result) => {
    if (err) {
      console.error("Create error:", err);
      if (err.code === 'ER_DUP_ENTRY') {
        return res.status(409).json({ error: "Phone number already exists" });
      }
      return res.status(500).json({ error: "Failed to create user." });
    }
    
    res.status(201).json({ 
      message: "User created successfully",
      userId: result.insertId 
    });
  });
});

// PUT update user
router.put("/:id", (req, res) => {
  const { id } = req.params;
  const { phone, fullname, email, role } = req.body;
  
  // Check if user exists first
  const checkQuery = "SELECT idaccount FROM account WHERE idaccount = ?";
  
  db.query(checkQuery, [id], (err, results) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ error: "Failed to check user." });
    }
    
    if (results.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }
    
    // Update user
    const updateQuery = "UPDATE account SET phone = ?, fullname = ?, email = ?, role = ? WHERE idaccount = ?";
    
    db.query(updateQuery, [phone, fullname, email || null, role || 'user', id], (err, result) => {
      if (err) {
        console.error("Update error:", err);
        if (err.code === 'ER_DUP_ENTRY') {
          return res.status(409).json({ error: "Phone number already exists" });
        }
        return res.status(500).json({ error: "Failed to update user." });
      }
      
      res.json({ message: "User updated successfully" });
    });
  });
});

// DELETE user
router.delete("/:id", (req, res) => {
  const { id } = req.params;
  
  const query = "DELETE FROM account WHERE idaccount = ?";
  
  db.query(query, [id], (err, result) => {
    if (err) {
      console.error("Delete error:", err);
      return res.status(500).json({ error: "Failed to delete user." });
    }
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "User not found" });
    }
    
    res.json({ message: "User deleted successfully" });
  });
});

// GET user by phone number
router.get("/phone/:phone", (req, res) => {
  const { phone } = req.params;
  const query = "SELECT idaccount, phone, fullname, email, role FROM account WHERE phone = ?";
  
  db.query(query, [phone], (err, results) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ error: "Failed to retrieve user." });
    }
    
    if (results.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }
    
    res.status(200).json(results[0]);
  });
});

// GET reading statistics for dashboard
router.get("/statistics", (req, res) => {
  const queries = {
    totalUsers: "SELECT COUNT(*) as count FROM account",
    totalAstrologyReadings: "SELECT COUNT(*) as count FROM userastrologyresults",
    totalNumerologyReadings: "SELECT COUNT(*) as count FROM usernumerologyresults",
    recentReadings: `
      SELECT 'astrology' as type, date FROM userastrologyresults 
      WHERE date >= DATE_SUB(NOW(), INTERVAL 7 DAY)
      UNION ALL
      SELECT 'numerology' as type, date FROM usernumerologyresults 
      WHERE date >= DATE_SUB(NOW(), INTERVAL 7 DAY)
    `
  };
  
  // Execute all queries
  Promise.all([
    new Promise((resolve, reject) => {
      db.query(queries.totalUsers, (err, results) => {
        if (err) reject(err);
        else resolve(results[0].count);
      });
    }),
    new Promise((resolve, reject) => {
      db.query(queries.totalAstrologyReadings, (err, results) => {
        if (err) reject(err);
        else resolve(results[0].count);
      });
    }),
    new Promise((resolve, reject) => {
      db.query(queries.totalNumerologyReadings, (err, results) => {
        if (err) reject(err);
        else resolve(results[0].count);
      });
    }),
    new Promise((resolve, reject) => {
      db.query(queries.recentReadings, (err, results) => {
        if (err) reject(err);
        else resolve(results.length);
      });
    })
  ])
  .then(([totalUsers, totalAstrology, totalNumerology, recentReadings]) => {
    res.status(200).json({
      totalUsers,
      totalAstrologyReadings: totalAstrology,
      totalNumerologyReadings: totalNumerology,
      totalReadings: totalAstrology + totalNumerology,
      recentReadings
    });
  })
  .catch(err => {
    console.error("Statistics error:", err);
    res.status(500).json({ error: "Failed to retrieve statistics." });
  });
});

module.exports = router;