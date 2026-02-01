const cloudinary = require('cloudinary').v2;

// Configure Cloudinary
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
});

/**
 * Uploads an image buffer to Cloudinary.
 * @param {Buffer} buffer - The file buffer.
 * @param {string} folder - The folder path in Cloudinary.
 * @returns {Promise<{url: string, publicId: string}>}
 */
const uploadImage = async (buffer, folder) => {
    return new Promise((resolve, reject) => {
        // Timeout handling (60 seconds)
        const timeout = setTimeout(() => {
            reject(new Error("Cloudinary upload timed out"));
        }, 60000);

        const uploadStream = cloudinary.uploader.upload_stream(
            {
                folder: folder,
                resource_type: 'image',
                // Removed 'format: auto' and 'quality: auto' - these are delivery parameters, not upload parameters
            },
            (error, result) => {
                clearTimeout(timeout);
                if (error) {
                    console.error('[UploadService] Cloudinary Error:', error);
                    return reject(error);
                }

                console.log(`[UploadService] Success: ${result.public_id} (${result.bytes} bytes)`);

                // Apply auto-format and auto-quality to the returned URL for optimized delivery
                const optimizedUrl = result.secure_url.replace('/upload/', '/upload/f_auto,q_auto/');

                resolve({
                    url: optimizedUrl,
                    publicId: result.public_id,
                });
            }
        );

        // Write buffer to stream
        uploadStream.end(buffer);
    });
};

module.exports = { uploadImage };
