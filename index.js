const express = require('express');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const users = require('./user');
const otps = require('./otps');

const app = express();
app.use(express.json());
app.use(cookieParser());

const PORT = 3000;
const secretKey = 'your_secret_key'; // Keep it secret in real apps

// OTP Generator
function generateOTP() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

// ---------- SIGNUP ----------
app.post('/signup', (req, res) => {
    const { name, email, mobile, password } = req.body;

    if (!name || !email || !mobile || !password) {
        return res.status(400).json({ message: 'All fields required' });
    }

    if (users[email] || users[mobile]) {
        return res.status(400).json({ message: 'User already exists' });
    }

    users[email] = { name, email, mobile, password, verified: false };

    const otp = generateOTP();
    otps[email] = { otp, expiresAt: Date.now() + 5 * 60 * 1000 };

    console.log(`OTP for ${email}: ${otp}`);
    res.status(200).json({ message: 'Signup successful. OTP sent to email (console).' });
});

// ---------- VERIFY OTP ----------
app.post('/verify-otp', (req, res) => {
    const { email, otp } = req.body;

    if (!email || !otp || !otps[email]) {
        return res.status(400).json({ message: 'Invalid OTP request' });
    }

    const record = otps[email];
    if (record.otp === otp && record.expiresAt > Date.now()) {
        users[email].verified = true;
        delete otps[email];
        return res.status(200).json({ message: 'OTP verified' });
    }

    res.status(400).json({ message: 'Invalid or expired OTP' });
});

// ---------- LOGIN ----------
app.post('/login', (req, res) => {
    const { emailOrMobile, password } = req.body;

    const user = Object.values(users).find(
        u => u.email === emailOrMobile || u.mobile === emailOrMobile
    );

    if (!user) {
        return res.status(400).json({ message: "User not found" });
    }

    if (user.password !== password) {
        return res.status(401).json({ message: "Incorrect password" });
    }

    if (!user.verified) {
        return res.status(403).json({ message: 'Please verify OTP first' });
    }

    const token = jwt.sign({ email: user.email }, secretKey, { expiresIn: '5m' });
    const refreshToken = jwt.sign({ email: user.email }, secretKey, { expiresIn: '1h' });

    res
        .cookie('token', token, { httpOnly: true })
        .cookie('refreshToken', refreshToken, { httpOnly: true })
        .json({ message: "Login successful" });
});

// ---------- REFRESH TOKEN ----------
app.post('/refresh-token', (req, res) => {
    const { refreshToken } = req.cookies;

    if (!refreshToken) {
        return res.status(401).json({ message: 'Refresh token missing' });
    }

    try {
        const decoded = jwt.verify(refreshToken, secretKey);
        const newToken = jwt.sign({ email: decoded.email }, secretKey, { expiresIn: '5m' });

        res.cookie('token', newToken, { httpOnly: true });
        res.json({ message: 'Token refreshed' });
    } catch (err) {
        res.status(403).json({ message: 'Invalid refresh token' });
    }
});

// ---------- MIDDLEWARE ----------
function authMiddleware(req, res, next) {
    const token = req.cookies.token;

    if (!token) {
        return res.status(401).json({ message: 'No token provided' });
    }

    try {
        const decoded = jwt.verify(token, secretKey);
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(403).json({ message: 'Invalid or expired token' });
    }
}

// ---------- PROTECTED ROUTE ----------
app.get('/protected', authMiddleware, (req, res) => {
    res.status(200).json({ message: `Hello ${req.user.email}, you're in protected route!` });
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
