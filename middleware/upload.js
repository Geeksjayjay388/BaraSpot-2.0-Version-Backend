// ===========================
// ADD THIS TO: middleware/upload.js
// ===========================

const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');

// ===========================
// CLOUDINARY CONFIGURATION
// ===========================
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME || 'your_cloud_name',
  api_key: process.env.CLOUDINARY_API_KEY || 'your_api_key',
  api_secret: process.env.CLOUDINARY_API_SECRET || 'your_api_secret'
});

// ===========================
// CLOUDINARY STORAGE CONFIGURATION
// ===========================
const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'secondlife-marketplace',
    allowed_formats: ['jpg', 'jpeg', 'png', 'webp'],
    transformation: [{ width: 800, height: 600, crop: 'limit' }]
  }
});

// ===========================
// MULTER CONFIGURATION
// ===========================
const upload = multer({ 
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024 // 5MB limit
  }
});

module.exports = upload;