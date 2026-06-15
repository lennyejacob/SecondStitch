const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const path = require('path');
const User = require('./models/User');

const app = express();

// 1. Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true })); // Parses form data
app.use(express.static(path.join(__dirname, 'public'))); // Serves your HTML files

// Session setup (keeps the user logged in)
app.use(session({
    secret: 'secondstitch_secret_key', // In a real app, hide this in a .env file!
    resave: false,
    saveUninitialized: false
}));

// 2. Connect to MongoDB (Replace with your actual MongoDB URI)
mongoose.connect('mongodb://127.0.0.1:27017/secondstitch')
    .then(() => console.log('✅ Connected to MongoDB'))
    .catch(err => console.error('❌ MongoDB Connection Error:', err));

// 3. Routes

// Sign Up Route
app.post('/signup', async (req, res) => {
    try {
        const { name, email, password, confirm_password } = req.body;

        if (password !== confirm_password) {
            return res.send('Passwords do not match. <a href="/signup.html">Try again</a>');
        }

        // Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.send('Email already in use. <a href="/login.html">Login</a>');
        }

        // Hash the password securely
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create and save new user
        const newUser = new User({ name, email, password: hashedPassword });
        await newUser.save();

        res.redirect('/login.html'); // Send them to login after successful signup
    } catch (error) {
        res.status(500).send('Error creating account.');
    }
});

// Login Route
app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Find the user
        const user = await User.findOne({ email });
        if (!user) {
            return res.send('Invalid email or password. <a href="/login.html">Try again</a>');
        }

        // Compare the hashed password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.send('Invalid email or password. <a href="/login.html">Try again</a>');
        }

        // Save user to session
        req.session.userId = user._id;
        
        // CHANGE THIS LINE:
        res.redirect('/index.html'); // <--- Now takes you to the home page!

    } catch (error) {
        res.status(500).send('Server error during login.');
    }
});

// --- NEW: Logout Route ---
app.get('/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/index.html'); 
    });
});

// --- NEW: Get logged-in user's data ---
app.get('/api/user', async (req, res) => {
    // If no one is logged in, send an error
    if (!req.session.userId) {
        return res.status(401).json({ message: 'Not logged in' });
    }
    try {
        // Find the user by the ID saved in their session
        const user = await User.findById(req.session.userId);
        res.json(user); // Send the user data to the browser
    } catch (err) {
        res.status(500).json({ message: 'Server error' });
    }
});

// --- NEW: Update Profile Route ---
app.post('/update-profile', async (req, res) => {
    if (!req.session.userId) return res.redirect('/login.html');
    
    try {
        // Update the user in the database with the new form data
        await User.findByIdAndUpdate(req.session.userId, {
            name: req.body.name,
            email: req.body.email
        });
        res.redirect('/profile.html'); // Refresh the page to show updates
    } catch (err) {
        res.status(500).send('Error updating profile');
    }
});

// Start Server
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
});