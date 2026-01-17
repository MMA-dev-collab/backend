const crypto = require('crypto');

/**
 * Extract client IP from request with security hardening
 * Handles trusted proxies, IPv6 normalization, and edge cases
 * 
 * @param {Request} req - Express request object
 * @returns {string} - Normalized IP address
 */
function getClientIP(req) {
    // Express 'trust proxy' setting populates req.ip correctly
    // If trust proxy is not set, req.ip defaults to req.socket.remoteAddress
    return normalizeIP(req.ip || req.socket?.remoteAddress || req.connection?.remoteAddress);
}

/**
 * Normalize IP addresses (handle IPv6-mapped IPv4 addresses)
 * Converts ::ffff:192.168.1.1 to 192.168.1.1
 * 
 * @param {string} ip - Raw IP address
 * @returns {string} - Normalized IP
 */
function normalizeIP(ip) {
    if (!ip) return '0.0.0.0';

    // Convert IPv6-mapped IPv4 (::ffff:192.168.1.1) to IPv4
    if (ip.startsWith('::ffff:')) {
        return ip.substring(7);
    }

    // Handle localhost variations
    if (ip === '::1') return '127.0.0.1';

    return ip;
}

/**
 * Validate IP address format
 * 
 * @param {string} ip - IP address to validate
 * @returns {boolean} - True if valid IPv4 or IPv6
 */
function isValidIP(ip) {
    if (!ip) return false;

    // IPv4 regex
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;

    // IPv6 regex (simplified - covers most cases)
    const ipv6Regex = /^([0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}$/i;

    return ipv4Regex.test(ip) || ipv6Regex.test(ip);
}

/**
 * Generate device fingerprint from request headers
 * Creates a consistent hash based on User-Agent and other browser signals
 * 
 * @param {Request} req - Express request object
 * @returns {string} - SHA-256 hash of device characteristics
 */
function getDeviceFingerprint(req) {
    const userAgent = req.headers['user-agent'] || 'unknown';
    const acceptLanguage = req.headers['accept-language'] || '';
    const acceptEncoding = req.headers['accept-encoding'] || '';

    // Create fingerprint string from browser characteristics
    const fingerprintData = `${userAgent}|${acceptLanguage}|${acceptEncoding}`;

    // Hash for consistent length and privacy
    return crypto.createHash('sha256').update(fingerprintData).digest('hex');
}

/**
 * Detect device type from User-Agent string
 * Used to determine whether to apply strict or fuzzy IP matching
 * 
 * @param {Request} req - Express request object
 * @returns {'mobile'|'tablet'|'desktop'} - Device type classification
 */
function getDeviceType(req) {
    const ua = (req.headers['user-agent'] || '').toLowerCase();

    // Mobile devices (phones)
    if (/mobile|android|iphone|ipod|blackberry|iemobile|opera mini/i.test(ua)) {
        return 'mobile';
    }

    // Tablets
    if (/tablet|ipad/i.test(ua)) {
        return 'tablet';
    }

    // Default to desktop
    return 'desktop';
}

/**
 * Match current device against stored device info
 * Implements fuzzy matching for mobile devices (IP can change)
 * and strict matching for desktop devices
 * 
 * @param {Object} storedDevice - { ip, fingerprint, last_seen }
 * @param {string} currentIP - Current request IP
 * @param {string} currentFingerprint - Current device fingerprint
 * @param {string} deviceType - 'mobile', 'tablet', or 'desktop'
 * @returns {boolean} - True if device matches
 */
function matchDevice(storedDevice, currentIP, currentFingerprint, deviceType) {
    // Slot is empty
    if (!storedDevice || !storedDevice.ip) {
        return false;
    }

    // Exact IP match always succeeds (strict mode)
    if (storedDevice.ip === currentIP) {
        return true;
    }

    // For mobile/tablet devices: allow fuzzy matching
    // Mobile IPs change frequently (WiFi <-> LTE, cell tower hops)
    if (deviceType === 'mobile' || deviceType === 'tablet') {
        // Same fingerprint + recent activity = same device despite IP change
        if (storedDevice.fingerprint === currentFingerprint) {
            // Check if device was active within last 24 hours
            if (storedDevice.last_seen) {
                const lastSeen = new Date(storedDevice.last_seen);
                const now = new Date();
                const hoursSinceLastSeen = (now - lastSeen) / (1000 * 60 * 60);

                // Allow if seen within 24 hours
                if (hoursSinceLastSeen <= 24) {
                    return true;
                }
            }
        }
    }

    // No match
    return false;
}

/**
 * Whitelist validator for SQL field names
 * Prevents SQL injection via dynamic field names
 * 
 * @param {string} field - Field name to validate
 * @returns {boolean} - True if field is in whitelist
 */
function isValidDeviceField(field) {
    const allowedFields = [
        'device1_ip',
        'device1_fingerprint',
        'device1_last_seen',
        'device2_ip',
        'device2_fingerprint',
        'device2_last_seen'
    ];

    return allowedFields.includes(field);
}

/**
 * Find available device slot for new device registration
 * 
 * @param {Object} user - User object with device1_* and device2_* fields
 * @returns {1|2|null} - Available slot number or null if both occupied
 */
function findAvailableSlot(user) {
    if (!user.device1_ip) {
        return 1;
    }
    if (!user.device2_ip) {
        return 2;
    }
    return null; // Both slots occupied
}

module.exports = {
    getClientIP,
    normalizeIP,
    isValidIP,
    getDeviceFingerprint,
    getDeviceType,
    matchDevice,
    isValidDeviceField,
    findAvailableSlot
};
