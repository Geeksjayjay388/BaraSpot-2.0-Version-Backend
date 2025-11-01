// ===========================
// ADD THIS TO: routes/items.js
// ===========================

const express = require('express');
const router = express.Router();
const Item = require('../models/Item');
const upload = require('../middleware/upload');

// ===========================
// GET ALL ITEMS (with filtering)
// Route: GET /api/items
// ===========================
router.get('/', async (req, res) => {
  try {
    const { 
      search = '', 
      condition = 'all', 
      category = 'all',
      location = 'all',
      minPrice,
      maxPrice,
      sortBy = 'newest',
      page = 1,
      limit = 20
    } = req.query;

    // Build query
    let query = { isActive: true };

    // Search functionality
    if (search) {
      query.$or = [
        { name: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } },
        { location: { $regex: search, $options: 'i' } }
      ];
    }

    // Filter by condition
    if (condition !== 'all' && condition !== '') {
      query.condition = condition;
    }

    // Filter by category
    if (category !== 'all' && category !== '') {
      query.category = category;
    }

    // Filter by location
    if (location !== 'all' && location !== '') {
      query.location = location;
    }

    // Price range filter
    if (minPrice || maxPrice) {
      query.price = {};
      if (minPrice) query.price.$gte = Number(minPrice);
      if (maxPrice) query.price.$lte = Number(maxPrice);
    }

    // Sort options
    let sortOptions = {};
    switch (sortBy) {
      case 'newest':
        sortOptions.createdAt = -1;
        break;
      case 'oldest':
        sortOptions.createdAt = 1;
        break;
      case 'price-low':
        sortOptions.price = 1;
        break;
      case 'price-high':
        sortOptions.price = -1;
        break;
      case 'rating':
        sortOptions.rating = -1;
        break;
      default:
        sortOptions.createdAt = -1;
    }

    // Pagination
    const skip = (Number(page) - 1) * Number(limit);

    const items = await Item.find(query)
      .sort(sortOptions)
      .skip(skip)
      .limit(Number(limit));

    const total = await Item.countDocuments(query);

    // Transform items to match frontend format
    const transformedItems = items.map(item => ({
      id: item._id,
      name: item.name,
      description: item.description,
      price: item.formattedPrice,
      originalPrice: item.formattedOriginalPrice,
      condition: item.condition.charAt(0).toUpperCase() + item.condition.slice(1),
      location: item.location,
      category: item.category,
      image: item.images[0]?.url || 'https://via.placeholder.com/400x400?text=No+Image',
      images: item.images.map(img => img.url),
      seller: item.seller.name,
      sellerPhone: item.seller.phone,
      rating: item.rating || (Math.random() * 1.5 + 3.5).toFixed(1),
      liked: item.liked,
      postedTime: item.postedTime,
      createdAt: item.createdAt
    }));

    res.json({
      success: true,
      data: transformedItems,
      pagination: {
        page: Number(page),
        limit: Number(limit),
        total,
        totalPages: Math.ceil(total / Number(limit))
      }
    });

  } catch (error) {
    console.error('Error fetching items:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching items',
      error: error.message
    });
  }
});

// ===========================
// GET SINGLE ITEM BY ID
// Route: GET /api/items/:id
// ===========================
router.get('/:id', async (req, res) => {
  try {
    const item = await Item.findById(req.params.id);
    
    if (!item) {
      return res.status(404).json({
        success: false,
        message: 'Item not found'
      });
    }

    const transformedItem = {
      id: item._id,
      name: item.name,
      description: item.description,
      price: item.formattedPrice,
      originalPrice: item.formattedOriginalPrice,
      condition: item.condition.charAt(0).toUpperCase() + item.condition.slice(1),
      location: item.location,
      category: item.category,
      image: item.images[0]?.url || 'https://via.placeholder.com/400x400?text=No+Image',
      images: item.images.map(img => img.url),
      seller: item.seller.name,
      sellerPhone: item.seller.phone,
      rating: item.rating || (Math.random() * 1.5 + 3.5).toFixed(1),
      liked: item.liked,
      postedTime: item.postedTime,
      createdAt: item.createdAt
    };

    res.json({
      success: true,
      data: transformedItem
    });

  } catch (error) {
    console.error('Error fetching item:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching item',
      error: error.message
    });
  }
});

// ===========================
// CREATE NEW ITEM (with image upload)
// Route: POST /api/items
// ===========================
router.post('/', upload.array('images', 5), async (req, res) => {
  try {
    const {
      name,
      description,
      price,
      originalPrice,
      condition,
      location,
      category,
      sellerName,
      sellerPhone
    } = req.body;

    // Validate required fields
    if (!name || !description || !price || !condition || !location || !category || !sellerName || !sellerPhone) {
      return res.status(400).json({
        success: false,
        message: 'All required fields must be provided'
      });
    }

    // Process uploaded images
    const images = req.files ? req.files.map(file => ({
      url: file.path,
      publicId: file.filename
    })) : [];

    // Create new item
    const newItem = new Item({
      name,
      description,
      price: Number(price),
      originalPrice: originalPrice ? Number(originalPrice) : undefined,
      condition: condition.toLowerCase(),
      location,
      category,
      images,
      seller: {
        name: sellerName,
        phone: sellerPhone
      }
    });

    const savedItem = await newItem.save();

    res.status(201).json({
      success: true,
      message: 'Item posted successfully!',
      data: {
        id: savedItem._id,
        name: savedItem.name,
        price: savedItem.formattedPrice,
        images: savedItem.images
      }
    });

  } catch (error) {
    console.error('Error creating item:', error);
    res.status(500).json({
      success: false,
      message: 'Error posting item',
      error: error.message
    });
  }
});

// ===========================
// TOGGLE LIKE/UNLIKE ITEM
// Route: PATCH /api/items/:id/like
// ===========================
router.patch('/:id/like', async (req, res) => {
  try {
    const item = await Item.findById(req.params.id);
    
    if (!item) {
      return res.status(404).json({
        success: false,
        message: 'Item not found'
      });
    }

    item.liked = !item.liked;
    await item.save();

    res.json({
      success: true,
      message: `Item ${item.liked ? 'liked' : 'unliked'}`,
      data: {
        id: item._id,
        liked: item.liked
      }
    });

  } catch (error) {
    console.error('Error toggling like:', error);
    res.status(500).json({
      success: false,
      message: 'Error updating item',
      error: error.message
    });
  }
});

// ===========================
// GET FILTERS DATA
// Route: GET /api/items/filters (need to handle this in server.js)
// This will be moved to a separate route
// ===========================

// ===========================
// DELETE ITEM (soft delete)
// Route: DELETE /api/items/:id
// ===========================
router.delete('/:id', async (req, res) => {
  try {
    const item = await Item.findById(req.params.id);
    
    if (!item) {
      return res.status(404).json({
        success: false,
        message: 'Item not found'
      });
    }

    item.isActive = false;
    await item.save();

    res.json({
      success: true,
      message: 'Item deleted successfully'
    });

  } catch (error) {
    console.error('Error deleting item:', error);
    res.status(500).json({
      success: false,
      message: 'Error deleting item',
      error: error.message
    });
  }
});

module.exports = router;