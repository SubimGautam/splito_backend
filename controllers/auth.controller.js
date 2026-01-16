const User = require('../models/User.model');
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'splito-secret-key-12345';

// Generate JWT Token
const generateToken = (userId, email) => {
  return jwt.sign(
    { id: userId, email },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
};

// Register User
exports.register = async (req, res) => {
  try {
    console.log('📝 Registration attempt:', req.body);
    
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Please provide email and password'
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message: 'Password must be at least 6 characters'
      });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: 'User already exists with this email'
      });
    }

    const user = new User({
      email: email.toLowerCase().trim(),
      password
    });

    await user.save();
    console.log('✅ User registered:', user.email);

    const token = generateToken(user._id, user.email);

    res.status(201).json({
      success: true,
      message: 'User registered successfully',
      data: {
        user: {
          id: user._id,
          email: user.email,
          createdAt: user.createdAt
        },
        token
      }
    });

  } catch (error) {
    console.error('❌ Registration error:', error);
    res.status(500).json({
      success: false,
      message: 'Error in registration',
      error: error.message
    });
  }
};

// Login User
exports.login = async (req, res) => {
  try {
    console.log('🔐 Login attempt:', req.body);
    
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Please provide email and password'
      });
    }

    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password'
      });
    }

    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password'
      });
    }

    console.log('✅ User logged in:', user.email);

    const token = generateToken(user._id, user.email);

    res.json({
      success: true,
      message: 'Login successful',
      data: {
        user: {
          id: user._id,
          email: user.email,
          createdAt: user.createdAt
        },
        token
      }
    });

  } catch (error) {
    console.error('❌ Login error:', error);
    res.status(500).json({
      success: false,
      message: 'Error in login',
      error: error.message
    });
  }
};

// Get User Profile
exports.getProfile = async (req, res) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    
    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'Access denied. No token provided.'
      });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    
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
};