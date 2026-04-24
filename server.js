/**
 * SCHMITZ RECHTSANWÄLTE - Enterprise API Gateway
 * Architecture inspired by top-tier legal institutional requirements.
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const xss = require('xss-clean');
const hpp = require('hpp');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 4000;

// 1. Institutional Security Middleware
app.use(helmet()); // Secure HTTP headers
app.use(xss()); // Prevent Cross-Site Scripting
app.use(hpp()); // Prevent HTTP Parameter Pollution
app.use(express.json({ limit: '10kb' })); // Restrict payload size

// Strict CORS for corporate domain only
const corsOptions = {
    origin: process.env.NODE_ENV === 'production' ? 'https://www.schmitz-recht.de' : 'http://localhost:3000',
    optionsSuccessStatus: 200
};
app.use(cors(corsOptions));

// Rate limiting to prevent DoS on intake endpoints
const intakeLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // Limit each IP to 5 requests per windowMs
    message: { error: 'Too many requests from this IP, please try again later.' }
});

// SMTP Configuration (Secure TLS)
const mailTransport = nodemailer.createTransport({
    host: process.env.CORPORATE_SMTP_HOST,
    port: process.env.CORPORATE_SMTP_PORT,
    secure: true, 
    auth: {
        user: process.env.CORPORATE_SMTP_USER,
        pass: process.env.CORPORATE_SMTP_PASS
    }
});

// 2. Secure Digital Intake API Endpoint
app.post('/api/v1/intake/submit', intakeLimiter, [
    // Strict input validation and sanitization
    body('email').isEmail().normalizeEmail().withMessage('Valid corporate or personal email required.'),
    body('practiceArea').isString().trim().escape().notEmpty(),
], async (req, res) => {
    
    // Validate request
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, errors: errors.array() });
    }

    const { email, practiceArea } = req.body;

    try {
        // Construct institutional internal notification
        const internalMailOptions = {
            from: '"Schmitz Digital Intake" <system@schmitz-recht.de>',
            to: 'intake@schmitz-recht.de',
            subject: `[SECURE INTAKE] Neues Mandatsangebot - ${practiceArea}`,
            text: `
                SYSTEM MELDUNG: Neue Mandatsanfrage.
                
                RECHTSGEBIET: ${practiceArea}
                KONTAKT: ${email}
                ZEITSTEMPEL: ${new Date().toISOString()}
                
                Bitte den standardisierten DSGVO-konformen Mandantenfragebogen an die oben genannte Adresse versenden.
            `
        };

        await mailTransport.sendMail(internalMailOptions);

        // Security Note: Never log PII (Personally Identifiable Information) in plain text to server logs.
        console.log(`[SYS-LOG] Intake processed successfully for practice area: ${practiceArea}`);

        // Return generic success to client
        res.status(200).json({ 
            success: true, 
            message: "Data encrypted and transmitted successfully." 
        });

    } catch (error) {
        console.error(`[SYS-ERROR] Intake processing failed:`, error.message);
        res.status(500).json({ success: false, message: "Internal server error during secure transmission." });
    }
});

// 3. Health Check for Load Balancers
app.get('/health', (req, res) => {
    res.status(200).json({ status: 'active', environment: process.env.NODE_ENV });
});

// 4. Start Server
app.listen(PORT, () => {
    console.log(`[SYS-INIT] Enterprise Legal Gateway operational on port ${PORT}`);
});
