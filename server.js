const express = require('express');
const app = express();
const mongoose = require('mongoose');
const cors = require('cors');
require('dotenv').config();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

app.use(cors());
app.use(express.json());

mongoose.connect(process.env.MONGODB_URL)
    .then(() => {
        app.listen(3000, () => {
            console.log("Connected to database and server running on port 3000");
        });
    })
    .catch((err) => {
        console.error("Database connection error:", err);
    });

app.get('/', (req, res) => {
    res.json({ msg: "Hello chicha" });
});

// Define the schema and model
const UserSchema = new mongoose.Schema(
    {
        institute: { type: String, required: true },
        email: { type: String, required: true, unique: true },
        password: { type: String, required: true },
        userRole: { type: String, default: 'user' },
    },
    { timestamps: true, collection: 'BlockCertify' } // Corrected the collection option placement
);

const UserModel = mongoose.model('UserData', UserSchema);

// Register route
app.post('/api/register', async (req, res) => {
    //console.log("Register request received:", req.body);
    try {
        const { institute, email, password } = req.body;

        // Check if the email already exists
        const existingUser = await UserModel.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ msg: "Email already in use" });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, parseInt(process.env.SALT));
        //console.log("Hashed password:", hashedPassword);

        // Create a new user
        const newUser = await UserModel.create({
            institute,
            email,
            password: hashedPassword,
        });
        //console.log("User created:", newUser);

        res.status(200).send({ msg: "User Created", user: newUser });
    } catch (err) {
        console.error("Error in registration:", err);
        res.status(500).json({
            status: 500,
            msg: "Registration failed",
            error: err.message
        });
    }
});

// LOGIN 
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    
    try {
        const user = await UserModel.findOne({ email });
        if (!user) {
            return res.status(401).json({ status: 'error', message: 'Invalid User' });
        }
        const HashPass = bcrypt.hash(password,parseInt(process.env.SALT))
        const isPasswordValid = await bcrypt.compare(password, user.password);
       
        if (HashPass === user.password) {
            return res.status(401).json({ status: 'error', message: 'Invalid Password' });
        }

        const token = jwt.sign(
            { userId: user }, // Changed to user._id to ensure only user ID is stored
            process.env.JWT_SECRET,
            { expiresIn: '15h' }
        );

        res.json({ status: true, token, userType: user.userRole, email: user.email });
    } catch (err) {
        console.error("Error in login:", err);
        res.status(500).json({ status: 'error', message: 'Login failed' });
    }
});


// Verify token
app.get('/api/verify-token', (req, res) => {
    // Retrieve the token from the Authorization header
    const token = req.headers['authorization'];

    if (!token) {
        return res.status(403).json({ status: 'error', message: 'No token provided' });
    }

    // Verify the token
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({ status: 'error', message: 'Failed to authenticate token' });
        }

        // Send back the decoded information if token is valid
        res.status(200).json({
            status: 'success',
            message: 'Token is valid',
            user: decoded  // Return the decoded user information
        });
    });
});
