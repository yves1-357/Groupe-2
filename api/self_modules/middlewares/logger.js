const fs = require('fs');
const path = require('path');

// Create logs directory if it doesn't exist
const logsDir = path.join(__dirname, '../../logs');
if (!fs.existsSync(logsDir)) {
    fs.mkdirSync(logsDir, { recursive: true });
}

const logFile = path.join(logsDir, 'access.log');

// Patterns that look suspicious
const SUSPICIOUS_PATTERNS = [
    /<script/i,
    /javascript:/i,
    /onerror=/i,
    /onload=/i,
    /svg.*onload/i,
    /document\.cookie/i,
    /fetch\(/i,
    /eval\(/i,
    /base64/i,
    /<img/i,
    /alert\(/i,
    /\.\.\//,           // Path traversal
    /union.*select/i,   // SQL injection attempt
    /drop.*table/i,
    /1=1/,
];

function isSuspicious(value) {
    if (typeof value !== 'string') return false;
    return SUSPICIOUS_PATTERNS.some(pattern => pattern.test(value));
}

function sanitizeBody(body) {
    if (!body || typeof body !== 'object') return body;
    const sanitized = { ...body };
    // Mask passwords
    if (sanitized.password) sanitized.password = '***MASKED***';
    return JSON.stringify(sanitized);
}

function checkPayloadSuspicious(body) {
    if (!body || typeof body !== 'object') return false;
    return Object.values(body).some(val => isSuspicious(String(val)));
}

module.exports = (req, res, callback) => {
    const now = new Date().toISOString();
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
    const method = req.method;
    const url = req.originalUrl || req.url;
    const userAgent = req.headers['user-agent'] || '-';
    const token = req.headers['token'] ? req.headers['token'].substring(0, 20) + '...' : 'none';

    // Intercept response to capture status code
    const originalEnd = res.end.bind(res);
    let statusCode = 200;

    res.end = function (...args) {
        statusCode = res.statusCode;

        const suspicious = checkPayloadSuspicious(req.body) 
            || isSuspicious(url) 
            || isSuspicious(JSON.stringify(req.query));

        const level = suspicious ? '[⚠️  SUSPICIOUS]' : '[INFO]';

        const logLine = [
            `[${now}]`,
            level,
            `IP=${ip}`,
            `${method} ${url}`,
            `STATUS=${statusCode}`,
            `TOKEN=${token}`,
            `BODY=${sanitizeBody(req.body)}`,
            `UA="${userAgent}"`,
        ].join(' | ') + '\n';

        // Write to log file (async, non-blocking)
        fs.appendFile(logFile, logLine, (err) => {
            if (err) console.error('[LOGGER] Could not write to log file:', err);
        });

        // Also print to console with color
        if (suspicious) {
            console.warn(`\x1b[33m${logLine.trim()}\x1b[0m`);
        } else {
            console.info(`\x1b[36m${logLine.trim()}\x1b[0m`);
        }

        return originalEnd(...args);
    };

    callback();
};
