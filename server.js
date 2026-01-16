const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = 5000;

// ========== MIDDLEWARE ==========
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Accept'],
  credentials: true
}));

app.use(express.json());

// Request logging middleware
app.use((req, res, next) => {
  console.log(`\n🌐 [${new Date().toISOString()}] ${req.method} ${req.url}`);
  if (req.body && Object.keys(req.body).length > 0) {
    console.log('📦 Body:', req.body);
  }
  next();
});

// ========== DATABASE CONNECTION ==========
mongoose.connect('mongodb://localhost:27017/splito_db')
  .then(() => {
    console.log('✅ MongoDB Connected Successfully');
    console.log('📊 Database: splito_db');
  })
  .catch(err => {
    console.error('❌ MongoDB Connection Error:', err.message);
  });

// ========== USER MODEL ==========
const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true
  },
  password: {
    type: String,
    required: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

const User = mongoose.model('User', userSchema);

// ========== JWT CONFIG ==========
const JWT_SECRET = 'splito-jwt-secret-key-2024';

// ========== ROUTES ==========

// Health Check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'OK',
    message: 'Splito Backend is running',
    timestamp: new Date().toISOString(),
    database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    endpoints: {
      register: 'POST /api/auth/register',
      login: 'POST /api/auth/login',
      health: 'GET /api/health'
    }
  });
});

// Register User
app.post('/api/auth/register', async (req, res) => {
  try {
    console.log('🔵 === REGISTER REQUEST ===');
    
    const { email, password } = req.body;
    
    // Validation
    if (!email || !password) {
      console.log('❌ Missing email or password');
      return res.status(400).json({
        success: false,
        message: 'Email and password are required'
      });
    }
    
    if (password.length < 6) {
      console.log('❌ Password too short');
      return res.status(400).json({
        success: false,
        message: 'Password must be at least 6 characters'
      });
    }
    
    // Check if user exists
    const existingUser = await User.findOne({ email: email.toLowerCase().trim() });
    if (existingUser) {
      console.log(`❌ User already exists: ${email}`);
      return res.status(400).json({
        success: false,
        message: 'User already exists with this email'
      });
    }
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    console.log('🔐 Password hashed');
    
    // Create user
    const user = new User({
      email: email.toLowerCase().trim(),
      password: hashedPassword
    });
    
    await user.save();
    console.log(`✅ User created: ${user.email}`);
    console.log(`📊 User ID: ${user._id}`);
    
    // Create JWT token
    const token = jwt.sign(
      {
        id: user._id,
        email: user.email
      },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    console.log('🔑 JWT Token generated');
    
    // Success response
    res.status(201).json({
      success: true,
      message: 'User registered successfully',
      data: {
        user: {
          id: user._id,
          email: user.email,
          createdAt: user.createdAt
        },
        token: token
      }
    });
    
    console.log('✅ === REGISTRATION COMPLETE ===\n');
    
  } catch (error) {
    console.error('❌ Registration error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error during registration',
      error: error.message
    });
  }
});

// Login User
app.post('/api/auth/login', async (req, res) => {
  try {
    console.log('🔵 === LOGIN REQUEST ===');
    
    const { email, password } = req.body;
    
    // Validation
    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Email and password are required'
      });
    }
    
    // Find user
    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (!user) {
      console.log(`❌ User not found: ${email}`);
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password'
      });
    }
    
    // Check password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      console.log(`❌ Invalid password for: ${email}`);
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password'
      });
    }
    
    console.log(`✅ User authenticated: ${user.email}`);
    
    // Create JWT token
    const token = jwt.sign(
      {
        id: user._id,
        email: user.email
      },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    
    // Success response
    res.json({
      success: true,
      message: 'Login successful',
      data: {
        user: {
          id: user._id,
          email: user.email,
          createdAt: user.createdAt
        },
        token: token
      }
    });
    
    console.log('✅ === LOGIN COMPLETE ===\n');
    
  } catch (error) {
    console.error('❌ Login error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error during login',
      error: error.message
    });
  }
});

// Get User Profile
app.get('/api/auth/profile', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    
    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'No token provided'
      });
    }
    
    // Verify token
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Find user
    const user = await User.findById(decoded.id).select('-password');
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    res.json({
      success: true,
      data: user
    });
    
  } catch (error) {
    console.error('❌ Profile error:', error);
    res.status(401).json({
      success: false,
      message: 'Invalid or expired token'
    });
  }
});

// ========== ERROR HANDLING ==========

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    message: 'Route not found'
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('🔥 Server Error:', err);
  res.status(500).json({
    success: false,
    message: 'Internal server error',
    error: err.message
  });
});

// ========== START SERVER ==========
app.listen(PORT, () => {
  console.log('\n🚀 ===== SPLITO BACKEND STARTED =====');
  console.log(`📡 Server running on: http://localhost:${PORT}`);
  console.log(`🔗 Health Check: http://localhost:${PORT}/api/health`);
  console.log(`🔐 Register: POST http://localhost:${PORT}/api/auth/register`);
  console.log(`🔓 Login: POST http://localhost:${PORT}/api/auth/login`);
  console.log('=====================================\n');
});