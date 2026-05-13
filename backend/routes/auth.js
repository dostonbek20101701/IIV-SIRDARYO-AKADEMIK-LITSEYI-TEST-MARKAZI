const express = require('express');
const pool = require('../config/database');
const { hashPassword, comparePassword, generateAccessToken, generateRefreshToken } = require('../config/auth');
const { validateInput } = require('../middleware/auth');

const router = express.Router();

// Register
router.post('/register', validateInput, async (req, res) => {
  try {
    const { fullName, email, password, role } = req.body;
    
    // Validation
    if (!fullName || !email || !password || !role) {
      return res.status(400).json({ success: false, message: 'Barcha maydonlar to\'ldirilishi kerak' });
    }
    
    if (!['teacher', 'student'].includes(role)) {
      return res.status(400).json({ success: false, message: 'Noto\'g\'ri rol' });
    }
    
    // Check if user exists
    const existingUser = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (existingUser.rows.length > 0) {
      return res.status(409).json({ success: false, message: 'Bu email allaqachon ro\'yxatdan o\'tgan' });
    }
    
    // Hash password
    const hashedPassword = await hashPassword(password);
    
    // Create user
    const result = await pool.query(
      'INSERT INTO users (full_name, email, password_hash, role, created_at) VALUES ($1, $2, $3, $4, NOW()) RETURNING id, email, role, full_name',
      [fullName, email, hashedPassword, role]
    );
    
    const user = result.rows[0];
    const accessToken = generateAccessToken(user.id, user.role);
    const refreshToken = generateRefreshToken(user.id);
    
    res.status(201).json({
      success: true,
      message: 'Foydalanuvchi muvaffaqiyatli ro\'yxatdan o\'ttii',
      user: { id: user.id, email: user.email, role: user.role, fullName: user.full_name },
      accessToken,
      refreshToken
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Server xatosi' });
  }
});

// Login
router.post('/login', validateInput, async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'Email va parol kerak' });
    }
    
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(401).json({ success: false, message: 'Email yoki parol noto\'g\'ri' });
    }
    
    const user = result.rows[0];
    const validPassword = await comparePassword(password, user.password_hash);
    
    if (!validPassword) {
      return res.status(401).json({ success: false, message: 'Email yoki parol noto\'g\'ri' });
    }
    
    const accessToken = generateAccessToken(user.id, user.role);
    const refreshToken = generateRefreshToken(user.id);
    
    res.json({
      success: true,
      message: 'Muvaffaqiyatli kirdingiz',
      user: { id: user.id, email: user.email, role: user.role, fullName: user.full_name },
      accessToken,
      refreshToken
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Server xatosi' });
  }
});

module.exports = router;
