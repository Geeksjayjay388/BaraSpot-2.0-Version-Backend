// ===========================
// FILE LOCATION: routes/admin.js
// DESCRIPTION: Admin authentication and management routes
// ===========================

const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// ===========================
// ADMIN CREDENTIALS
// ===========================
const ADMIN_CREDENTIALS = {
  username: 'jacob',
  // Password: YOUR PASSWORD (the one you just used)
  passwordHash: '$2b$10$XkiN3c6TjWg98JltX.EvE.ZHvxKTDMeBPEMboAEBxrHpHFbI9F1v6'
};

// JWT Secret from environment variables
const JWT_SECRET = process.env.JWT_SECRET;

// ===========================
// MIDDLEWARE: Verify Admin Token
// ===========================
const verifyAdmin = (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'No token provided'
      });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    
    if (!decoded.isAdmin) {
      return res.status(403).json({
        success: false,
        message: 'Access denied. Admin only.'
      });
    }

    req.admin = decoded;
    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: 'Invalid or expired token'
    });
  }
};

// ===========================
// POST /api/admin/login
// Admin login endpoint
// ===========================
router.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Validate input
    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message: 'Username and password are required'
      });
    }

    // Check username
    if (username !== ADMIN_CREDENTIALS.username) {
      // Don't reveal which field is wrong for security
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    // Check password
    const isValid = await bcrypt.compare(password, ADMIN_CREDENTIALS.passwordHash);
    
    if (!isValid) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    // Generate JWT token
    const token = jwt.sign(
      { 
        username: username,
        isAdmin: true 
      },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    console.log('✅ Admin login successful:', username);

    res.json({
      success: true,
      message: 'Login successful',
      token,
      admin: { username }
    });

  } catch (error) {
    console.error('❌ Login error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error during login'
    });
  }
});

// ===========================
// GET /api/admin/verify
// Verify if token is still valid
// ===========================
router.get('/verify', verifyAdmin, (req, res) => {
  res.json({
    success: true,
    message: 'Token is valid',
    admin: { username: req.admin.username }
  });
});

// ===========================
// GET /api/admin/stats
// Get admin dashboard statistics
// ===========================
router.get('/stats', verifyAdmin, async (req, res) => {
  try {
    const Item = require('../models/Item');

    const [totalItems, activeItems, likedItems] = await Promise.all([
      Item.countDocuments(),
      Item.countDocuments({ isActive: true }),
      Item.countDocuments({ liked: true })
    ]);

    // Category breakdown
    const categoryStats = await Item.aggregate([
      {
        $group: {
          _id: '$category',
          count: { $sum: 1 },
          totalValue: { $sum: '$price' }
        }
      },
      { $sort: { count: -1 } }
    ]);

    // Recent items
    const recentItems = await Item.find()
      .sort({ createdAt: -1 })
      .limit(5)
      .select('name price category createdAt');

    res.json({
      success: true,
      data: {
        totalItems,
        activeItems,
        inactiveItems: totalItems - activeItems,
        likedItems,
        categoryStats,
        recentItems
      }
    });

  } catch (error) {
    console.error('Error fetching admin stats:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching statistics'
    });
  }
});

module.exports = router;
module.exports.verifyAdmin = verifyAdmin;