module.exports = (sessions) => (req, res, next) => {
    const token = req.cookies.token;

    if (!token || !sessions[token]) {
        return res.status(401).json({ message: 'Unauthorized' });
    }

    req.user = { email: sessions[token].email };
    next();
};
