// ===========================
// FILE LOCATION: server.js (ROOT DIRECTORY)
// DESCRIPTION: Main server file with CORS properly configured
// ===========================

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');
require('dotenv').config();

const app = express();

// ===========================
// CORS CONFIGURATION - FIXED!
// Allow all origins during development
// ===========================
app.use(cors({
  origin: [
    'http://localhost:3000', 
    'http://localhost:5173',
    'http://localhost:5183', 
    'http://127.0.0.1:3000',
    'http://127.0.0.1:5173',
    'http://127.0.0.1:5183'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept']
}));

// Handle preflight requests
app.options('*', cors());

// ===========================
// MIDDLEWARE SETUP
// ===========================
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Serve static files (for uploaded images if needed)
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// ===========================
// DATABASE CONNECTION
// Connect to MongoDB using credentials from .env file
// ===========================
const MONGODB_URI = process.env.MONGODB_URI;

mongoose.connect(MONGODB_URI)
  .then(() => {
    console.log('✅ Connected to MongoDB');
    console.log(`📊 Database: ${mongoose.connection.name}`);
  })
  .catch(err => {
    console.error('❌ MongoDB connection error:', err);
    process.exit(1);
  });

// ===========================
// IMPORT ROUTES
// Load route handlers from separate files
// ===========================
const itemRoutes = require('./routes/items');

// ===========================
// API ROUTES
// ===========================

// Health check route - Test if server is running
app.get('/api/health', (req, res) => {
  res.json({
    success: true,
    message: 'SecondLife API is running!',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
    cors: 'enabled'
  });
});

// Connect item routes to /api/items path
app.use('/api/items', itemRoutes);

// Get filters data (categories, locations, etc.)
app.get('/api/filters', async (req, res) => {
  try {
    const Item = require('./models/Item');
    
    // Get unique categories, conditions, and locations from existing items
    const [categories, conditions, locations] = await Promise.all([
      Item.distinct('category', { isActive: true }),
      Item.distinct('condition', { isActive: true }),
      Item.distinct('location', { isActive: true })
    ]);

    // Get price range
    const priceStats = await Item.aggregate([
      { $match: { isActive: true } },
      {
        $group: {
          _id: null,
          minPrice: { $min: '$price' },
          maxPrice: { $max: '$price' }
        }
      }
    ]);

    const priceRange = priceStats.length > 0 
      ? { min: priceStats[0].minPrice, max: priceStats[0].maxPrice }
      : { min: 0, max: 100000 };

    // Default categories if none exist
    const defaultCategories = [
      'Electronics', 'Clothing', 'Furniture', 'Books', 'Sports', 
      'Toys', 'Automotive', 'Home & Garden', 'Health & Beauty', 'Other'
    ];

    // Default conditions
    const defaultConditions = ['excellent', 'good', 'fair'];

    // Default locations (Kenyan cities)
    const defaultLocations = [
      'Nairobi', 'Mombasa', 'Kisumu', 'Nakuru', 'Eldoret', 
      'Thika', 'Malindi', 'Kitale', 'Garissa', 'Kakamega'
    ];

    res.json({
      success: true,
      data: {
        categories: categories.length > 0 ? categories : defaultCategories,
        conditions: conditions.length > 0 ? conditions : defaultConditions,
        locations: locations.length > 0 ? locations : defaultLocations,
        priceRange
      }
    });

  } catch (error) {
    console.error('Error fetching filters:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching filters',
      error: error.message
    });
  }
});

// Get statistics for dashboard
app.get('/api/stats', async (req, res) => {
  try {
    const Item = require('./models/Item');

    const stats = await Item.aggregate([
      { $match: { isActive: true } },
      {
        $group: {
          _id: null,
          totalItems: { $sum: 1 },
          averagePrice: { $avg: '$price' },
          totalValue: { $sum: '$price' },
          likedItems: { $sum: { $cond: ['$liked', 1, 0] } }
        }
      }
    ]);

    // Get category breakdown
    const categoryBreakdown = await Item.aggregate([
      { $match: { isActive: true } },
      {
        $group: {
          _id: '$category',
          count: { $sum: 1 },
          averagePrice: { $avg: '$price' }
        }
      },
      { $sort: { count: -1 } }
    ]);

    const result = stats.length > 0 ? stats[0] : {
      totalItems: 0,
      averagePrice: 0,
      totalValue: 0,
      likedItems: 0
    };

    res.json({
      success: true,
      data: {
        ...result,
        averagePrice: Math.round(result.averagePrice || 0),
        totalValue: Math.round(result.totalValue || 0),
        categoryBreakdown
      }
    });

  } catch (error) {
    console.error('Error fetching stats:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching statistics',
      error: error.message
    });
  }
});

// ===========================
// ERROR HANDLING MIDDLEWARE
// ===========================

// Handle 404 errors
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    message: `Route ${req.originalUrl} not found`,
    availableRoutes: [
      'GET /api/health',
      'GET /api/items',
      'GET /api/items/:id',
      'POST /api/items',
      'PATCH /api/items/:id/like',
      'DELETE /api/items/:id',
      'GET /api/filters',
      'GET /api/stats'
    ]
  });
});

// Global error handler
app.use((error, req, res, next) => {
  console.error('Global error handler:', error);
  
  res.status(error.status || 500).json({
    success: false,
    message: error.message || 'Internal server error',
    ...(process.env.NODE_ENV === 'development' && { stack: error.stack })
  });
});

// ===========================
// GRACEFUL SHUTDOWN
// ===========================
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  mongoose.connection.close(() => {
    console.log('MongoDB connection closed');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('SIGINT received, shutting down gracefully');
  mongoose.connection.close(() => {
    console.log('MongoDB connection closed');
    process.exit(0);
  });
});

// ===========================
// START SERVER
// ===========================
const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`📡 API Base URL: http://localhost:${PORT}/api`);
  console.log(`🔗 CORS enabled for: http://localhost:3000`);
  console.log('\n📋 Available endpoints:');
  console.log('   GET  /api/health - Check server status');
  console.log('   GET  /api/items - Get all items');
  console.log('   POST /api/items - Create new item');
  console.log('   GET  /api/items/:id - Get single item');
  console.log('   PATCH /api/items/:id/like - Like/unlike item');
  console.log('   DELETE /api/items/:id - Delete item');
  console.log('   GET  /api/filters - Get filter options');
  console.log('   GET  /api/stats - Get statistics');
});