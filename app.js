const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');
require('dotenv').config();

const app = express();

app.use(helmet());
app.use(express.json());
app.use(cookieParser());

// Allow multiple origins for development
app.use(cors({
  origin: [
    'http://localhost:5173',  // Vite default
    'http://localhost:3000',  // React default
    'http://localhost',       // Your current frontend
    'http://localhost:8080',  // Common dev server
    'https://goldeneden.io.vn'
  ],
  credentials: true
}));

// Rest of your routes...
const authRoutes = require('./routes/auth');
app.use('/api/auth', authRoutes);

const numerologyRoutes = require('./routes/numerology');
app.use('/api/numerology', numerologyRoutes);

const astrologyRoutes = require('./routes/astrology');
app.use('/api/astrology', astrologyRoutes);

const dashBoardRoutes = require('./routes/dashboard');
app.use('/api/users', dashBoardRoutes);

const fs = require('fs');
const mysql = require('mysql2/promise');

// Check if database tables exist
async function checkDatabaseExists() {
  try {
    const connection = await mysql.createConnection({
      host: process.env.MYSQLHOST,
      port: process.env.MYSQLPORT,
      user: process.env.MYSQLUSER,
      password: process.env.MYSQLPASSWORD,
      database: process.env.MYSQLDATABASE
    });

    // Check if any tables exist (you can modify this to check for specific tables)
    const [tables] = await connection.execute('SHOW TABLES');
    await connection.end();
    
    return tables.length > 0;
  } catch (err) {
    console.error('❌ Lỗi khi kiểm tra database:', err.message);
    return false;
  }
}

// Initialize database from init.sql file only if needed
async function initDB() {
  try {
    const dbExists = await checkDatabaseExists();
    
    if (dbExists) {
      console.log('✅ Database đã tồn tại, bỏ qua việc khởi tạo.');
      return;
    }

    console.log('🔄 Database chưa tồn tại, đang khởi tạo...');
    
    const sql = fs.readFileSync('./init.sql', 'utf-8');

    const connection = await mysql.createConnection({
      host: process.env.MYSQLHOST,
      port: process.env.MYSQLPORT,
      user: process.env.MYSQLUSER,
      password: process.env.MYSQLPASSWORD,
      database: process.env.MYSQLDATABASE,
      multipleStatements: true
    });

    await connection.query(sql);
    console.log('✅ Đã import thành công file init.sql vào MySQL.');
    await connection.end();
  } catch (err) {
    console.error('❌ Lỗi import SQL:', err.message);
  }
}

initDB().then(() => {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
});