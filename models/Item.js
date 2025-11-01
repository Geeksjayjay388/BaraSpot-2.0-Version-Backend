// ===========================
// ADD THIS TO: models/Item.js
// ===========================

const mongoose = require('mongoose');

// ===========================
// ITEM SCHEMA DEFINITION
// ===========================
const itemSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  description: {
    type: String,
    required: true
  },
  price: {
    type: Number,
    required: true
  },
  originalPrice: {
    type: Number
  },
  condition: {
    type: String,
    required: true,
    enum: ['excellent', 'good', 'fair']
  },
  location: {
    type: String,
    required: true
  },
  category: {
    type: String,
    required: true
  },
  images: [{
    url: String,
    publicId: String
  }],
  seller: {
    name: {
      type: String,
      required: true
    },
    phone: {
      type: String,
      required: true
    }
  },
  rating: {
    type: Number,
    default: 0
  },
  reviewCount: {
    type: Number,
    default: 0
  },
  liked: {
    type: Boolean,
    default: false
  },
  isActive: {
    type: Boolean,
    default: true
  }
}, {
  timestamps: true
});

// ===========================
// VIRTUAL FIELDS
// ===========================

// Add virtual for formatted price
itemSchema.virtual('formattedPrice').get(function() {
  return `Ksh ${this.price.toLocaleString()}`;
});

// Add virtual for formatted original price
itemSchema.virtual('formattedOriginalPrice').get(function() {
  return this.originalPrice ? `Ksh ${this.originalPrice.toLocaleString()}` : null;
});

// Add virtual for posted time
itemSchema.virtual('postedTime').get(function() {
  const now = new Date();
  const posted = new Date(this.createdAt);
  const diffInMs = now - posted;
  const diffInHours = Math.floor(diffInMs / (1000 * 60 * 60));
  const diffInDays = Math.floor(diffInHours / 24);
  const diffInWeeks = Math.floor(diffInDays / 7);

  if (diffInHours < 1) return 'Just now';
  if (diffInHours < 24) return `${diffInHours} hour${diffInHours > 1 ? 's' : ''} ago`;
  if (diffInDays < 7) return `${diffInDays} day${diffInDays > 1 ? 's' : ''} ago`;
  if (diffInWeeks < 4) return `${diffInWeeks} week${diffInWeeks > 1 ? 's' : ''} ago`;
  return posted.toLocaleDateString();
});

// ===========================
// ENSURE VIRTUAL FIELDS ARE SERIALIZED
// ===========================
itemSchema.set('toJSON', { virtuals: true });

module.exports = mongoose.model('Item', itemSchema);