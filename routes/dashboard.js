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
  
  // Handle role: if role is 'user' or not provided, set to null
  const roleValue = (role === 'admin') ? 'admin' : null;
  
  const query = "INSERT INTO account (phone, fullname, password, email, role) VALUES (?, ?, ?, ?, ?)";
  
  db.query(query, [phone, fullname, password, email || null, roleValue], (err, result) => {
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
    
    // Handle role: if role is 'user', null, undefined, or empty, set to null
    // Only set to 'admin' if explicitly provided as 'admin'
    const roleValue = (role === 'admin') ? 'admin' : null;
    
    // Update user
    const updateQuery = "UPDATE account SET phone = ?, fullname = ?, email = ?, role = ? WHERE idaccount = ?";
    
    db.query(updateQuery, [phone, fullname, email || null, roleValue, id], (err, result) => {
      if (err) {
        console.error("Update error:", err);
        if (err.code === 'ER_DUP_ENTRY') {
          return res.status(409).json({ error: "Phone number already exists" });
        }
        return res.status(500).json({ error: "Failed to update user." });
      }
      
      res.json({ 
        message: "User updated successfully",
        updatedRole: roleValue
      });
    });
  });
});

// DELETE user
router.delete("/:id", (req, res) => {
  const { id } = req.params;

  // Truy vấn để lấy số điện thoại dựa trên idaccount
  const getPhoneQuery = "SELECT phone FROM account WHERE idaccount = ?";
  db.query(getPhoneQuery, [id], (err, rows) => {
    if (err) {
      console.error("Error fetching phone:", err);
      return res.status(500).json({ error: "Failed to get user phone." });
    }

    if (rows.length === 0) {
      return res.status(404).json({ error: "User not found." });
    }

    const phone = rows[0].phone;

    // Xóa các dòng trong userastrologyresults trước
    const deleteResultsQuery = "DELETE FROM userastrologyresults WHERE PhoneNumber = ?";
    db.query(deleteResultsQuery, [phone], (err) => {
      if (err) {
        console.error("Error deleting astrology results:", err);
        return res.status(500).json({ error: "Failed to delete related astrology results." });
      }

      // Sau khi xóa thành công thì xóa account
      const deleteAccountQuery = "DELETE FROM account WHERE idaccount = ?";
      db.query(deleteAccountQuery, [id], (err, result) => {
        if (err) {
          console.error("Delete error:", err);
          return res.status(500).json({ error: "Failed to delete user." });
        }

        if (result.affectedRows === 0) {
          return res.status(404).json({ error: "User not found" });
        }

        res.json({ message: "User and related results deleted successfully" });
      });
    });
  });
});

// PATCH route specifically for role toggle (alternative approach)
router.patch("/:id/role", (req, res) => {
  const { id } = req.params;
  const { role } = req.body;
  
  // Validate role value
  const validRoles = ['admin', 'user', null];
  if (role !== undefined && !validRoles.includes(role)) {
    return res.status(400).json({ error: "Invalid role. Must be 'admin', 'user', or null." });
  }
  
  // Convert 'user' to null for database storage
  const roleValue = (role === 'admin') ? 'admin' : null;
  
  const query = "UPDATE account SET role = ? WHERE idaccount = ?";
  
  db.query(query, [roleValue, id], (err, result) => {
    if (err) {
      console.error("Role update error:", err);
      return res.status(500).json({ error: "Failed to update user role." });
    }
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "User not found" });
    }
    
    res.json({ 
      message: "User role updated successfully",
      newRole: roleValue,
      displayRole: roleValue === 'admin' ? 'admin' : 'user'
    });
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