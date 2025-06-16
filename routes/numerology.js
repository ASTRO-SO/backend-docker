const express = require("express");
const db = require("../db"); // MySQL pool or connection
const router = express.Router();

// Helper function to get title and description from database
const getMeaningFromTable = (tableName, number) => {
  return new Promise((resolve, reject) => {
    const query = `SELECT Title, Description FROM ${tableName} WHERE Number = ? LIMIT 1`;
    
    db.query(query, [number], (err, results) => {
      if (err) {
        console.error(`Error fetching from ${tableName}:`, err);
        resolve({ title: "", description: "" });
      } else {
        const result = results.length > 0 ? results[0] : { Title: "", Description: "" };
        resolve({ 
          title: result.Title || "", 
          description: result.Description || "" 
        });
      }
    });
  });
};

// Helper function to save numerology result to database
const saveNumerologyResult = (data) => {
  return new Promise((resolve, reject) => {
    // First check if the phone number exists in account table (if provided)
    if (data.phoneNumber) {
      const checkUserQuery = "SELECT phone FROM account WHERE phone = ? LIMIT 1";
      
      db.query(checkUserQuery, [data.phoneNumber], (checkErr, checkResults) => {
        if (checkErr) {
          console.error("Error checking user existence:", checkErr);
          // Still proceed but without phone number
          insertWithoutPhone();
          return;
        }

        if (checkResults.length === 0) {
          console.log(`Phone number ${data.phoneNumber} not found in account table, saving without phone number`);
          // Phone number doesn't exist in account table, save without it
          insertWithoutPhone();
        } else {
          // Phone number exists, proceed with normal insert
          insertWithPhone();
        }
      });
    } else {
      // No phone number provided, insert without it
      insertWithoutPhone();
    }

    function insertWithPhone() {
      const query = `
        INSERT INTO usernumerologyresults (
          PhoneNumber, lifepath_number, destiny_number, soulurge_number, 
          personality_number, naturalability_number, maturity_number, 
          attitude_number, challenge_number_1, challenge_number_2, 
          challenge_number_3, challenge_number_4, date
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
      `;
      
      const values = [
        data.phoneNumber,
        data.lifePathNumber,
        data.destinyNumber,
        data.soulUrgeNumber,
        data.personalityNumber,
        data.naturalAbilityNumber,
        data.maturityNumber,
        data.attitudeNumber,
        data.challenges.challenge1,
        data.challenges.challenge2,
        data.challenges.challenge3,
        data.challenges.challenge4
      ];

      db.query(query, values, (err, result) => {
        if (err) {
          console.error("Error saving numerology result with phone:", err);
          reject(err);
        } else {
          console.log("Numerology result saved with phone number");
          resolve(result.insertId);
        }
      });
    }

    function insertWithoutPhone() {
      const query = `
        INSERT INTO usernumerologyresults (
          lifepath_number, destiny_number, soulurge_number, 
          personality_number, naturalability_number, maturity_number, 
          attitude_number, challenge_number_1, challenge_number_2, 
          challenge_number_3, challenge_number_4, date
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
      `;
      
      const values = [
        data.lifePathNumber,
        data.destinyNumber,
        data.soulUrgeNumber,
        data.personalityNumber,
        data.naturalAbilityNumber,
        data.maturityNumber,
        data.attitudeNumber,
        data.challenges.challenge1,
        data.challenges.challenge2,
        data.challenges.challenge3,
        data.challenges.challenge4
      ];

      db.query(query, values, (err, result) => {
        if (err) {
          console.error("Error saving numerology result without phone:", err);
          reject(err);
        } else {
          console.log("Numerology result saved without phone number");
          resolve(result.insertId);
        }
      });
    }
  });
};

// @route   POST /api/numerology/calculate
// @desc    Calculate numerology and fetch meanings from database
// @access  Public
router.post("/calculate", async (req, res) => {
  const { fullName, date, numbers, phoneNumber } = req.body;

  if (!fullName || !date || !numbers) {
    return res.status(400).json({ error: "Missing required fields." });
  }

  try {
    // Fetch meanings from database for each number type
    const [
      lifePathData,
      destinyData,
      soulUrgeData,
      personalityData,
      naturalAbilityData,
      maturityData,
      attitudeData,
      challenge1Data,
      challenge2Data,
      challenge3Data,
      challenge4Data
    ] = await Promise.all([
      getMeaningFromTable('lifepath_number', numbers.lifePathNumber),
      getMeaningFromTable('destiny_number', numbers.destinyNumber),
      getMeaningFromTable('soulurge_number', numbers.soulUrgeNumber),
      getMeaningFromTable('personality_number', numbers.personalityNumber),
      getMeaningFromTable('naturalability_number', numbers.naturalAbilityNumber),
      getMeaningFromTable('maturity_number', numbers.maturityNumber),
      getMeaningFromTable('attitude_number', numbers.attitudeNumber),
      getMeaningFromTable('challenge_number', numbers.challenge1),
      getMeaningFromTable('challenge_number', numbers.challenge2),
      getMeaningFromTable('challenge_number', numbers.challenge3),
      getMeaningFromTable('challenge_number', numbers.challenge4)
    ]);

    // Prepare response data
    const responseData = {
      fullName,
      date,
      phoneNumber,
      lifePathNumber: numbers.lifePathNumber,
      lifePathTitle: lifePathData.title,
      lifePathDescription: lifePathData.description,
      
      destinyNumber: numbers.destinyNumber,
      destinyTitle: destinyData.title,
      destinyDescription: destinyData.description,
      
      soulUrgeNumber: numbers.soulUrgeNumber,
      soulUrgeTitle: soulUrgeData.title,
      soulUrgeDescription: soulUrgeData.description,
      
      personalityNumber: numbers.personalityNumber,
      personalityTitle: personalityData.title,
      personalityDescription: personalityData.description,
      
      naturalAbilityNumber: numbers.naturalAbilityNumber,
      naturalAbilityTitle: naturalAbilityData.title,
      naturalAbilityDescription: naturalAbilityData.description,
      
      maturityNumber: numbers.maturityNumber,
      maturityTitle: maturityData.title,
      maturityDescription: maturityData.description,
      
      attitudeNumber: numbers.attitudeNumber,
      attitudeTitle: attitudeData.title,
      attitudeDescription: attitudeData.description,
      
      challenges: {
        challenge1: numbers.challenge1,
        challenge1Title: challenge1Data.title,
        challenge1Description: challenge1Data.description,
        
        challenge2: numbers.challenge2,
        challenge2Title: challenge2Data.title,
        challenge2Description: challenge2Data.description,
        
        challenge3: numbers.challenge3,
        challenge3Title: challenge3Data.title,
        challenge3Description: challenge3Data.description,
        
        challenge4: numbers.challenge4,
        challenge4Title: challenge4Data.title,
        challenge4Description: challenge4Data.description
      }
    };

    // Save the result to database
    try {
      const savedResultId = await saveNumerologyResult(responseData);
      console.log(`Numerology result saved with ID: ${savedResultId}`);
      
      // Add the saved ID to response
      responseData.savedResultId = savedResultId;
      
    } catch (saveError) {
      // Log the error but don't fail the entire request
      console.error("Failed to save numerology result:", saveError);
      // You can choose to add a warning to the response or just log it
      responseData.saveWarning = "Result calculated successfully but could not be saved to history";
    }

    res.status(200).json({
      success: true,
      data: responseData
    });

  } catch (error) {
    console.error("Error calculating numerology:", error);
    res.status(500).json({ error: "Failed to calculate numerology." });
  }
});

// @route   GET /api/numerology/history/:phoneNumber
// @desc    Get numerology calculation history for a phone number
// @access  Public
router.get("/history/:phoneNumber", (req, res) => {
  const { phoneNumber } = req.params;
  const { limit = 10, offset = 0 } = req.query;

  if (!phoneNumber) {
    return res.status(400).json({ error: "Phone number is required." });
  }

  const query = `
    SELECT ResultID, PhoneNumber, lifepath_number, destiny_number, 
           soulurge_number, personality_number, naturalability_number, 
           maturity_number, attitude_number, challenge_number_1, 
           challenge_number_2, challenge_number_3, challenge_number_4, date
    FROM usernumerologyresults 
    WHERE PhoneNumber = ? 
    ORDER BY date DESC 
    LIMIT ? OFFSET ?
  `;

  db.query(query, [phoneNumber, parseInt(limit), parseInt(offset)], (err, results) => {
    if (err) {
      console.error("Error fetching history:", err);
      return res.status(500).json({ error: "Failed to retrieve history." });
    }

    // Format results to group challenge numbers for consistency with frontend
    const formattedResults = results.map(result => ({
      ...result,
      challenge_numbers: {
        challenge1: result.challenge_number_1,
        challenge2: result.challenge_number_2,
        challenge3: result.challenge_number_3,
        challenge4: result.challenge_number_4
      }
    }));

    res.status(200).json({
      success: true,
      data: formattedResults,
      total: formattedResults.length
    });
  });
});

// @route   GET /api/numerology/result/:id
// @desc    Get specific numerology result by ID
// @access  Public
router.get("/result/:id", (req, res) => {
  const { id } = req.params;

  const query = `
    SELECT * FROM usernumerologyresults WHERE ResultID = ? LIMIT 1
  `;

  db.query(query, [id], (err, results) => {
    if (err) {
      console.error("Error fetching result:", err);
      return res.status(500).json({ error: "Failed to retrieve result." });
    }

    if (results.length === 0) {
      return res.status(404).json({ error: "Result not found." });
    }

    const result = results[0];
    
    // Format challenge numbers for consistency with frontend
    result.challenge_numbers = {
      challenge1: result.challenge_number_1,
      challenge2: result.challenge_number_2,
      challenge3: result.challenge_number_3,
      challenge4: result.challenge_number_4
    };

    res.status(200).json({
      success: true,
      data: result
    });
  });
});

// @route   DELETE /api/numerology/result/:id
// @desc    Delete specific numerology result by ID
// @access  Public
router.delete("/result/:id", (req, res) => {
  const { id } = req.params;

  const query = "DELETE FROM usernumerologyresults WHERE ResultID = ?";
  
  db.query(query, [id], (err, result) => {
    if (err) {
      console.error("Delete result error:", err);
      return res.status(500).json({ error: "Failed to delete result." });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "Result not found." });
    }

    res.json({ 
      success: true, 
      message: "Result deleted successfully" 
    });
  });
});

// @route   GET /api/numerology/system
// @desc    Fetch all numerology systems
// @access  Public
router.get("/system", (req, res) => {
  const query = "SELECT id, name, description FROM numerology";

  db.query(query, (err, results) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ error: "Failed to retrieve data." });
    }

    res.status(200).json(results);
  });
});


// @route   POST /api/numerology/meanings/:table
// @desc    Add or update meaning for a specific number in a specific table
// @access  Public
router.get("/meanings/:number", async (req, res) => {
  const { number } = req.params;
  
  try {
    // First get all systems
    const systemsQuery = "SELECT id, name FROM numerology ORDER BY id";
    
    db.query(systemsQuery, (err, systems) => {
      if (err) {
        console.error("Systems fetch error:", err);
        return res.status(500).json({ error: "Failed to retrieve systems." });
      }

      const meaningPromises = systems.map(system => {
        return new Promise((resolve, reject) => {
          const tableName = system.name.toLowerCase(); 
          const query = `SELECT description FROM ${tableName} WHERE Number = ? LIMIT 1`;
          
          db.query(query, [number], (err, results) => {
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
          res.json({ number, meanings: meaningArray });
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

router.post("/meanings/:number", async (req, res) => {
  const { number } = req.params;
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
          const updateQuery = `UPDATE ${tableName} SET description = ? WHERE Number = ?`;
          
          db.query(updateQuery, [meaning, number], (err, result) => {
            if (err) {
              console.error(`Error updating ${tableName}:`, err);
              resolve(false);
            } else if (result.affectedRows === 0) {
              // No existing record, insert new one
              const insertQuery = `INSERT INTO ${tableName} (Number, description) VALUES (?, ?)`;
              db.query(insertQuery, [number, meaning], (insertErr, insertResult) => {
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
            message: `Successfully updated ${successCount}/${systems.length} meanings for ${number}`,
            number,
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

// @route   DELETE /api/numerology/meanings/:table/:number
// @desc    Delete meaning for a specific number from a specific table
// @access  Public
router.delete("/meanings/:table/:number", (req, res) => {
  const { table, number } = req.params;
  
  // Validate table name
  const allowedTables = [
    'lifepath_number',
    'destiny_number', 
    'soulurge_number',
    'personality_number',
    'naturalability_number',
    'maturity_number',
    'attitude_number',
    'challenge_number'
  ];
  
  if (!allowedTables.includes(table)) {
    return res.status(400).json({ error: "Invalid table name." });
  }

  const query = `DELETE FROM ${table} WHERE Number = ?`;
  
  db.query(query, [number], (err, result) => {
    if (err) {
      console.error(`Delete error from ${table}:`, err);
      return res.status(500).json({ error: "Failed to delete meaning." });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "Meaning not found." });
    }

    res.json({ message: "Meaning deleted successfully" });
  });
});

// Legacy routes (keeping for backward compatibility)
router.put("/:id", (req, res) => {
  const { id } = req.params;
  const { name, description } = req.body;

  const query = "UPDATE numerology SET name = ?, description = ? WHERE id = ?";
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

  const query = "DELETE FROM numerology WHERE id = ?";
  db.query(query, [id], (err, result) => {
    if (err) {
      console.error("Delete error:", err);
      return res.status(500).json({ error: "Failed to delete system." });
    }

    res.json({ message: "System deleted successfully" });
  });
});

router.post("/", (req, res) => {
  const { name, description } = req.body;

  if (!name || !description) {
    return res.status(400).json({ error: "Name and description are required." });
  }

  const insertQuery = "INSERT INTO numerology (name, description) VALUES (?, ?)";

  db.query(insertQuery, [name, description], (err, result) => {
    if (err) {
      console.error("Insert error:", err);
      return res.status(500).json({ error: "Failed to add new numerology system." });
    }

    res.status(201).json({
      message: "Numerology system added successfully",
      id: result.insertId,
    });
  });
});

// GET all numerology readings for management dashboard
router.get("/readings", (req, res) => {
  const query = `
    SELECT 
      ResultID,
      PhoneNumber,
      lifepath_number,
      soulurge_number,
      personality_number,
      naturalability_number,
      maturity_number,
      attitude_number,
      destiny_number,
      challenge_number_1,
      challenge_number_2,
      challenge_number_3,
      challenge_number_4,
      date
    FROM usernumerologyresults 
    ORDER BY date DESC
  `;
  
  db.query(query, (err, results) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ error: "Failed to retrieve numerology readings." });
    }
    
    res.status(200).json(results);
  });
});

// GET single numerology reading by ID
router.get("/readings/:id", (req, res) => {
  const { id } = req.params;
  const query = `
    SELECT 
      ResultID,
      PhoneNumber,
      lifepath_number,
      soulurge_number,
      personality_number,
      naturalability_number,
      maturity_number,
      attitude_number,
      destiny_number,
      challenge_number_1,
      challenge_number_2,
      challenge_number_3,
      challenge_number_4,
      date
    FROM usernumerologyresults 
    WHERE ResultID = ?
  `;
  
  db.query(query, [id], (err, results) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ error: "Failed to retrieve numerology reading." });
    }
    
    if (results.length === 0) {
      return res.status(404).json({ error: "Numerology reading not found" });
    }
    
    res.status(200).json(results[0]);
  });
});

// GET numerology readings by phone number
router.get("/readings/phone/:phone", (req, res) => {
  const { phone } = req.params;
  const query = `
    SELECT 
      ResultID,
      PhoneNumber,
      lifepath_number,
      soulurge_number,
      personality_number,
      naturalability_number,
      maturity_number,
      attitude_number,
      destiny_number,
      challenge_number_1,
      challenge_number_2,
      challenge_number_3,
      challenge_number_4,
      date
    FROM usernumerologyresults 
    WHERE PhoneNumber = ?
    ORDER BY date DESC
  `;
  
  db.query(query, [phone], (err, results) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ error: "Failed to retrieve numerology readings." });
    }
    
    res.status(200).json(results);
  });
});

module.exports = router;