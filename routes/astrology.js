const express = require("express");
const db = require("../db"); // MySQL pool or connection
const router = express.Router();

// @route   GET /api/astrology
// @desc    Fetch all astrology systems
// @access  Public
router.get("/system", (req, res) => {
  const query = "SELECT id, name, description FROM astrology";

  db.query(query, (err, results) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ error: "Failed to retrieve data." });
    }

    res.status(200).json(results);
  });
});


// @route   POST /api/astrology/save-results
// @desc    Save user astrology results to database
// @access  Public
router.post("/save-results", (req, res) => {
  const {
    PhoneNumber,
    date,
    ascendant,
    chiron,
    jupiter,
    mars,
    mercury,
    moon,
    neptune,
    pluto,
    saturn,
    sun,
    venus
  } = req.body;

  // Validate required fields - including PhoneNumber
  if (!date || !sun || !moon || !ascendant || !PhoneNumber) {
    return res.status(400).json({ 
      error: "Missing required fields", 
      required: ["date", "sun", "moon", "ascendant", "PhoneNumber"] 
    });
  }

  console.log('Saving user astrology results:', req.body);

  const insertQuery = `
    INSERT INTO userastrologyresults 
    (PhoneNumber, date, ascendant, chiron, jupiter, mars, mercury, moon, neptune, pluto, saturn, sun, venus) 
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `;

  const values = [
    PhoneNumber, // Remove || null since it's now required
    date,
    ascendant,
    chiron,
    jupiter,
    mars,
    mercury,
    moon,
    neptune,
    pluto,
    saturn,
    sun,
    venus
  ];

  db.query(insertQuery, values, (err, result) => {
    if (err) {
      console.error("Error saving user astrology results:", err);
      return res.status(500).json({ 
        error: "Failed to save astrology results",
        details: err.message 
      });
    }

    console.log('User astrology results saved successfully:', result.insertId);
    
    res.status(201).json({
      message: "User astrology results saved successfully",
      id: result.insertId,
      data: {
        PhoneNumber,
        date,
        ascendant,
        chiron,
        jupiter,
        mars,
        mercury,
        moon,
        neptune,
        pluto,
        saturn,
        sun,
        venus
      }
    });
  });
});

// @route   GET /api/astrology/user-results
// @desc    Get all user astrology results
// @access  Public
router.get("/user-results", (req, res) => {
  const query = "SELECT * FROM userastrologyresults ORDER BY created_at DESC";

  db.query(query, (err, results) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ error: "Failed to retrieve user results." });
    }

    res.status(200).json(results);
  });
});

// @route   GET /api/astrology/user-results/:phone
// @desc    Get user astrology results by phone number
// @access  Public
router.get("/user-results/:phone", (req, res) => {
  const { phone } = req.params;
  
  const query = "SELECT * FROM userastrologyresults WHERE PhoneNumber = ? ORDER BY created_at DESC";

  db.query(query, [phone], (err, results) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ error: "Failed to retrieve user results." });
    }

    if (results.length === 0) {
      return res.status(404).json({ 
        error: "No results found for this phone number" 
      });
    }

    res.status(200).json(results);
  });
});

// @route   DELETE /api/astrology/user-results/:id
// @desc    Delete user astrology result by ID
// @access  Public
router.delete("/user-results/:id", (req, res) => {
  const { id } = req.params;

  const query = "DELETE FROM userastrologyresults WHERE id = ?";
  
  db.query(query, [id], (err, result) => {
    if (err) {
      console.error("Delete error:", err);
      return res.status(500).json({ error: "Failed to delete user result." });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "User result not found." });
    }

    res.json({ message: "User result deleted successfully" });
  });
});

router.get("/:planet/:zodiac", (req, res) => {
  const { planet, zodiac } = req.params;
  
  console.log(`Fetching interpretation for ${planet} in ${zodiac}`);
  
  // Validate planet name (table name)
  const validPlanets = ['sun', 'moon', 'mercury', 'venus', 'mars', 'jupiter', 'saturn', 'neptune', 'pluto', 'chiron', 'ascendant'];
  
  if (!validPlanets.includes(planet.toLowerCase())) {
    return res.status(400).json({ error: "Invalid planet name" });
  }

  const tableName = planet.toLowerCase();
  const query = `SELECT Description FROM ${tableName} WHERE ZodiacSign = ? LIMIT 1`;
  
  db.query(query, [zodiac], (err, results) => {
    if (err) {
      console.error(`Error fetching from ${tableName}:`, err);
      return res.status(500).json({ error: "Failed to retrieve interpretation." });
    }
    
    if (results.length === 0) {
      return res.status(404).json({ 
        error: "No interpretation found",
        description: `Không tìm thấy giải thích cho ${planet} trong ${zodiac}`
      });
    }
    
    res.status(200).json({ 
      planet,
      zodiac,
      description: results[0].Description 
    });
  });
});

// @route   GET /api/astrology/meanings/:zodiac
// @desc    Fetch meanings for a specific zodiac sign
// @access  Public
router.get("/meanings/:zodiac", async (req, res) => {
  const { zodiac } = req.params;
  
  try {
    // First get all systems
    const systemsQuery = "SELECT id, name FROM astrology ORDER BY id";
    
    db.query(systemsQuery, (err, systems) => {
      if (err) {
        console.error("Systems fetch error:", err);
        return res.status(500).json({ error: "Failed to retrieve systems." });
      }

      // For each system, get the meaning from its corresponding table
      const meaningPromises = systems.map(system => {
        return new Promise((resolve, reject) => {
          // Assuming each system has a table with the same name as the system
          const tableName = system.name.toLowerCase(); // e.g., 'sun', 'moon', etc.
          const query = `SELECT description FROM ${tableName} WHERE ZodiacSign = ? LIMIT 1`;
          
          db.query(query, [zodiac], (err, results) => {
            if (err) {
              console.error(`Error fetching from ${tableName}:`, err);
              resolve({ systemId: system.id, meaning: "" }); // Return empty string on error
            } else {
              const meaning = results.length > 0 ? results[0].description : "";
              resolve({ systemId: system.id, meaning });
            }
          });
        });
      });

      Promise.all(meaningPromises)
        .then(meanings => {
          // Sort by systemId to maintain order
          meanings.sort((a, b) => a.systemId - b.systemId);
          const meaningArray = meanings.map(m => m.meaning);
          res.json({ zodiac, meanings: meaningArray });
        })
        .catch(err => {
          console.error("Error fetching meanings:", err);
          res.status(500).json({ error: "Failed to retrieve meanings." });
        });
    });
  } catch (err) {
    console.error("Meanings fetch error:", err);
    res.status(500).json({ error: "Failed to retrieve meanings." });
  }
});

// @route   POST /api/astrology/meanings/:zodiac
// @desc    Save meanings for a specific zodiac sign
// @access  Public
router.post("/meanings/:zodiac", async (req, res) => {
  const { zodiac } = req.params;
  const { meanings } = req.body; // Array of meanings corresponding to each system
  
  try {
    // First get all systems to know which tables to update
    const systemsQuery = "SELECT id, name FROM astrology ORDER BY id";
    
    db.query(systemsQuery, (err, systems) => {
      if (err) {
        console.error("Systems fetch error:", err);
        return res.status(500).json({ error: "Failed to retrieve systems." });
      }

      // Update each system's table with the corresponding meaning
      const updatePromises = systems.map((system, index) => {
        return new Promise((resolve, reject) => {
          const tableName = system.name.toLowerCase();
          const meaning = meanings[index] || "";
          
          // First try to update existing record
          const updateQuery = `UPDATE ${tableName} SET description = ? WHERE ZodiacSign = ?`;
          
          db.query(updateQuery, [meaning, zodiac], (err, result) => {
            if (err) {
              console.error(`Error updating ${tableName}:`, err);
              resolve(false);
            } else if (result.affectedRows === 0) {
              // No existing record, insert new one
              const insertQuery = `INSERT INTO ${tableName} (ZodiacSign, description) VALUES (?, ?)`;
              db.query(insertQuery, [zodiac, meaning], (insertErr, insertResult) => {
                if (insertErr) {
                  console.error(`Error inserting into ${tableName}:`, insertErr);
                  resolve(false);
                } else {
                  resolve(true);
                }
              });
            } else {
              resolve(true);
            }
          });
        });
      });

      Promise.all(updatePromises)
        .then(results => {
          const successCount = results.filter(r => r).length;
          res.json({ 
            message: `Successfully updated ${successCount}/${systems.length} meanings for ${zodiac}`,
            zodiac,
            updated: successCount
          });
        })
        .catch(err => {
          console.error("Error saving meanings:", err);
          res.status(500).json({ error: "Failed to save meanings." });
        });
    });
  } catch (err) {
    console.error("Meanings save error:", err);
    res.status(500).json({ error: "Failed to save meanings." });
  }
});

router.put("/:id", (req, res) => {
  const { id } = req.params;
  const { name, description } = req.body;

  const query = "UPDATE astrology SET name = ?, description = ? WHERE id = ?";
  db.query(query, [name, description, id], (err, result) => {
    if (err) {
      console.error("Update error:", err);
      return res.status(500).json({ error: "Failed to update system." });
    }

    res.json({ message: "System updated successfully" });
  });
});

router.delete("/:id", (req, res) => {
  const { id } = req.params;

  const query = "DELETE FROM astrology WHERE id = ?";
  db.query(query, [id], (err, result) => {
    if (err) {
      console.error("Delete error:", err);
      return res.status(500).json({ error: "Failed to delete system." });
    }

    res.json({ message: "System deleted successfully" });
  });
});

// @route   POST /api/astrology
// @desc    Add a new astrology system
// @access  Public (optional: protect with auth later)
router.post("/", (req, res) => {
  const { name, description } = req.body;

  if (!name || !description) {
    return res.status(400).json({ error: "Name and description are required." });
  }

  const insertQuery = "INSERT INTO astrology (name, description) VALUES (?, ?)";

  db.query(insertQuery, [name, description], (err, result) => {
    if (err) {
      console.error("Insert error:", err);
      return res.status(500).json({ error: "Failed to add new astrology system." });
    }

    res.status(201).json({
      message: "Astrology system added successfully",
      id: result.insertId,
    });
  });
});

router.get("/readings", (req, res) => {
  const query = `
    SELECT 
      ResultID,
      PhoneNumber,
      date,
      ascendant,
      chiron,
      jupiter,
      mars,
      mercury,
      moon,
      neptune,
      pluto,
      saturn,
      sun,
      venus
    FROM userastrologyresults 
    ORDER BY date DESC
  `;
  
  db.query(query, (err, results) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ error: "Failed to retrieve astrology readings." });
    }
    
    res.status(200).json(results);
  });
});

// GET single astrology reading by ID
router.get("/readings/:id", (req, res) => {
  const { id } = req.params;
  const query = `
    SELECT 
      ResultID,
      PhoneNumber,
      date,
      ascendant,
      chiron,
      jupiter,
      mars,
      mercury,
      moon,
      neptune,
      pluto,
      saturn,
      sun,
      venus
    FROM userastrologyresults 
    WHERE ResultID = ?
  `;
  
  db.query(query, [id], (err, results) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ error: "Failed to retrieve astrology reading." });
    }
    
    if (results.length === 0) {
      return res.status(404).json({ error: "Astrology reading not found" });
    }
    
    res.status(200).json(results[0]);
  });
});

// GET astrology readings by phone number
router.get("/readings/phone/:phone", (req, res) => {
  const { phone } = req.params;
  const query = `
    SELECT 
      ResultID,
      PhoneNumber,
      date,
      ascendant,
      chiron,
      jupiter,
      mars,
      mercury,
      moon,
      neptune,
      pluto,
      saturn,
      sun,
      venus
    FROM userastrologyresults 
    WHERE PhoneNumber = ?
    ORDER BY date DESC
  `;
  
  db.query(query, [phone], (err, results) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ error: "Failed to retrieve astrology readings." });
    }
    
    res.status(200).json(results);
  });
});

module.exports = router;