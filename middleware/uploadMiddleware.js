const multer = require('multer');
const path = require('path');
const sizeOf = require('image-size');

// 1. Configure Multer (Memory Storage)
const storage = multer.memoryStorage();

// Allowed MIME types and Extensions
const ALLOWED_MIME_TYPES = ['image/jpeg', 'image/png', 'image/webp', 'image/jpg'];
const ALLOWED_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.webp'];

const fileFilter = (req, file, cb) => {
    // MIME Check
    if (!ALLOWED_MIME_TYPES.includes(file.mimetype)) {
        return cb(new Error('INVALID_FILE_TYPE: Only JPEG, PNG, and WebP are allowed'), false);
    }

    // Extension Check (Double check to prevent spoofing)
    const ext = path.extname(file.originalname).toLowerCase();
    if (!ALLOWED_EXTENSIONS.includes(ext)) {
        return cb(new Error('INVALID_FILE_EXTENSION: Extension does not match allowed types'), false);
    }

    cb(null, true);
};

const upload = multer({
    storage: storage,
    limits: {
        fileSize: 5 * 1024 * 1024, // 5MB Limit
    },
    fileFilter: fileFilter,
});

// 2. Dimension Validation Middleware
const validateImageDimensions = (req, res, next) => {
    if (!req.file) {
        return next(); // Multer might have failed or no file sent (handled by controller validation if needed)
    }

    try {
        const dimensions = sizeOf(req.file.buffer);
        const MAX_DIMENSION = 5000;

        if (dimensions.width > MAX_DIMENSION || dimensions.height > MAX_DIMENSION) {
            return res.status(400).json({
                message: `Image dimensions too large. Max ${MAX_DIMENSION}x${MAX_DIMENSION}px allowed.`
            });
        }
        next();
    } catch (err) {
        console.error('[UploadMiddleware] Dimension check failed:', err);
        return res.status(400).json({ message: `Invalid image file (could not read dimensions): ${err.message}` });
    }
};

module.exports = {
    uploadMiddleware: upload.single('image'), // Expect entry 'image'
    validateImageDimensions,
};
