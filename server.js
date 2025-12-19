const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('✅ Connected to MongoDB'))
.catch((err) => console.error('❌ MongoDB connection error:', err));

// User Schema
const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
  },
  password: {
    type: String,
    required: true,
  },
  name: {
    type: String,
    required: true,
  },
  phoneNumber: {
    type: String,
    default: '',
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

const User = mongoose.model('User', userSchema);

// Drop old username index if it exists (run once on startup)
User.collection.dropIndex('username_1').catch(() => {
  // Index doesn't exist, that's fine
  console.log('No username index to drop (expected)');
});

// Listing Schema
const listingSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true,
  },
  description: {
    type: String,
    required: true,
  },
  monthlyRent: {
    type: Number,
    required: true,
  },
  propertyType: {
    type: String,
    enum: ['apartment', 'house', 'villa', 'cabin'],
    default: 'apartment',
  },
  location: {
    address: {
      type: String,
      required: true,
    },
    coordinates: {
      latitude: {
        type: Number,
        required: true,
      },
      longitude: {
        type: Number,
        required: true,
      },
    },
  },
  images: [{
    type: String, // Will store base64 or URLs
  }],
  amenities: [{
    type: String,
  }],
  phoneNumber: {
    type: String,
    default: '',
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
  status: {
    type: String,
    enum: ['active', 'inactive', 'rented'],
    default: 'active',
  },
});

const Listing = mongoose.model('Listing', listingSchema);

// Bid Schema
const bidSchema = new mongoose.Schema({
  listingId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Listing',
    required: true,
  },
  bidderId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  amount: {
    type: Number,
    required: true,
  },
  message: {
    type: String,
    default: '',
  },
  status: {
    type: String,
    enum: ['pending', 'accepted', 'rejected', 'withdrawn'],
    default: 'pending',
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

const Bid = mongoose.model('Bid', bidSchema);

// Routes

// Health check
app.get('/', (req, res) => {
  res.json({ message: 'Server is running!' });
});

// Register
app.post('/api/register', async (req, res) => {
  try {
    console.log('Registration attempt - Body:', { ...req.body, password: '***' });
    
    const { email, password, name } = req.body;

    // Validation
    if (!email || !password || !name) {
      console.log('Validation failed - missing fields');
      return res.status(400).json({ error: 'All fields are required' });
    }

    // Check if user already exists
    console.log('Checking if user exists:', email);
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      console.log('User already exists:', email);
      return res.status(400).json({ error: 'User already exists' });
    }

    // Hash password
    console.log('Hashing password...');
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const user = new User({
      email,
      password: hashedPassword,
      name,
    });

    await user.save();

    // Generate token
    const token = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.status(201).json({
      message: 'User registered successfully',
      token,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
      },
    });
  } catch (error) {
    console.error('Register error:', error);
    console.error('Error stack:', error.stack);
    console.error('Error message:', error.message);
    res.status(500).json({ 
      error: 'Server error',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validation
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    // Check password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    // Generate token
    const token = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
      },
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Verify token middleware
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

// Get user profile (protected route)
app.get('/api/profile', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('-password');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({ user });
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// ===== LISTING ROUTES =====

// Create a new listing (protected)
app.post('/api/listings', verifyToken, async (req, res) => {
  try {
    const {
      title,
      description,
      monthlyRent,
      propertyType,
      location,
      images,
      amenities,
      phoneNumber,
    } = req.body;

    // Validation
    if (!title || !description || !monthlyRent || !location) {
      return res.status(400).json({ error: 'All required fields must be filled' });
    }

    if (!location.address || !location.coordinates || 
        !location.coordinates.latitude || !location.coordinates.longitude) {
      return res.status(400).json({ error: 'Location with coordinates is required' });
    }

    // Create listing
    const listing = new Listing({
      title,
      description,
      monthlyRent: parseFloat(monthlyRent),
      propertyType: propertyType || 'apartment',
      location,
      images: images || [],
      amenities: amenities || [],
      phoneNumber: phoneNumber || '',
      userId: req.userId,
    });

    await listing.save();

    res.status(201).json({
      message: 'Listing created successfully',
      listing,
    });
  } catch (error) {
    console.error('Create listing error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get all listings (public)
app.get('/api/listings', async (req, res) => {
  try {
    const { status } = req.query;
    const filter = status ? { status } : { status: 'active' };
    
    const listings = await Listing.find(filter)
      .populate('userId', 'name email phoneNumber')
      .sort({ createdAt: -1 });

    res.json({ listings });
  } catch (error) {
    console.error('Get listings error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get single listing by ID (public)
app.get('/api/listings/:id', async (req, res) => {
  try {
    const listing = await Listing.findById(req.params.id)
      .populate('userId', 'name email phoneNumber');

    if (!listing) {
      return res.status(404).json({ error: 'Listing not found' });
    }

    res.json({ listing });
  } catch (error) {
    console.error('Get listing error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get user's own listings (protected)
app.get('/api/my-listings', verifyToken, async (req, res) => {
  try {
    const listings = await Listing.find({ userId: req.userId })
      .sort({ createdAt: -1 });

    res.json({ listings });
  } catch (error) {
    console.error('Get my listings error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Update listing (protected)
app.put('/api/listings/:id', verifyToken, async (req, res) => {
  try {
    const listing = await Listing.findById(req.params.id);

    if (!listing) {
      return res.status(404).json({ error: 'Listing not found' });
    }

    // Check if user owns the listing
    if (listing.userId.toString() !== req.userId) {
      return res.status(403).json({ error: 'Not authorized to update this listing' });
    }

    // Update fields
    const allowedUpdates = [
      'title',
      'description',
      'monthlyRent',
      'propertyType',
      'location',
      'images',
      'amenities',
      'phoneNumber',
      'status',
    ];

    allowedUpdates.forEach((field) => {
      if (req.body[field] !== undefined) {
        listing[field] = req.body[field];
      }
    });

    await listing.save();

    res.json({
      message: 'Listing updated successfully',
      listing,
    });
  } catch (error) {
    console.error('Update listing error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Delete listing (protected)
app.delete('/api/listings/:id', verifyToken, async (req, res) => {
  try {
    const listing = await Listing.findById(req.params.id);

    if (!listing) {
      return res.status(404).json({ error: 'Listing not found' });
    }

    // Check if user owns the listing
    if (listing.userId.toString() !== req.userId) {
      return res.status(403).json({ error: 'Not authorized to delete this listing' });
    }

    await Listing.findByIdAndDelete(req.params.id);

    res.json({ message: 'Listing deleted successfully' });
  } catch (error) {
    console.error('Delete listing error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// ===== BID ROUTES =====

// Create a new bid (protected)
app.post('/api/bids', verifyToken, async (req, res) => {
  try {
    const { listingId, amount, message } = req.body;

    // Validation
    if (!listingId || !amount) {
      return res.status(400).json({ error: 'Listing ID and amount are required' });
    }

    // Check if listing exists
    const listing = await Listing.findById(listingId);
    if (!listing) {
      return res.status(404).json({ error: 'Listing not found' });
    }

    // Check if user is trying to bid on their own listing
    if (listing.userId.toString() === req.userId) {
      return res.status(400).json({ error: 'You cannot bid on your own listing' });
    }

    // Validate bid amount (must be at least 60% of asking price)
    const minimumBid = listing.monthlyRent * 0.6;
    if (parseFloat(amount) < minimumBid) {
      return res.status(400).json({ 
        error: `Bid must be at least 60% of the asking price ($${minimumBid.toFixed(2)})` 
      });
    }

    // Create bid
    const bid = new Bid({
      listingId,
      bidderId: req.userId,
      amount: parseFloat(amount),
      message: message || '',
    });

    await bid.save();

    // Populate bidder info
    await bid.populate('bidderId', 'name email');
    await bid.populate('listingId', 'title monthlyRent');

    res.status(201).json({
      message: 'Bid created successfully',
      bid,
    });
  } catch (error) {
    console.error('Create bid error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get bids for a listing (protected - only listing owner)
app.get('/api/listings/:id/bids', verifyToken, async (req, res) => {
  try {
    const listing = await Listing.findById(req.params.id);

    if (!listing) {
      return res.status(404).json({ error: 'Listing not found' });
    }

    // Check if user owns the listing
    if (listing.userId.toString() !== req.userId) {
      return res.status(403).json({ error: 'Not authorized to view bids for this listing' });
    }

    const bids = await Bid.find({ listingId: req.params.id })
      .populate('bidderId', 'name email')
      .sort({ createdAt: -1 });

    res.json({ bids });
  } catch (error) {
    console.error('Get listing bids error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get user's own bids (protected)
app.get('/api/my-bids', verifyToken, async (req, res) => {
  try {
    const bids = await Bid.find({ bidderId: req.userId })
      .populate('listingId', 'title monthlyRent location images')
      .sort({ createdAt: -1 });

    res.json({ bids });
  } catch (error) {
    console.error('Get my bids error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Update bid status (protected - only listing owner)
app.put('/api/bids/:id', verifyToken, async (req, res) => {
  try {
    const bid = await Bid.findById(req.params.id).populate('listingId');

    if (!bid) {
      return res.status(404).json({ error: 'Bid not found' });
    }

    // Check if user owns the listing
    if (bid.listingId.userId.toString() !== req.userId) {
      return res.status(403).json({ error: 'Not authorized to update this bid' });
    }

    const { status } = req.body;
    if (!['pending', 'accepted', 'rejected', 'withdrawn'].includes(status)) {
      return res.status(400).json({ error: 'Invalid status' });
    }

    bid.status = status;
    await bid.save();

    await bid.populate('bidderId', 'name email');

    res.json({
      message: 'Bid updated successfully',
      bid,
    });
  } catch (error) {
    console.error('Update bid error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Withdraw bid (protected - only bidder)
app.delete('/api/bids/:id', verifyToken, async (req, res) => {
  try {
    const bid = await Bid.findById(req.params.id);

    if (!bid) {
      return res.status(404).json({ error: 'Bid not found' });
    }

    // Check if user is the bidder
    if (bid.bidderId.toString() !== req.userId) {
      return res.status(403).json({ error: 'Not authorized to delete this bid' });
    }

    // Mark as withdrawn instead of deleting
    bid.status = 'withdrawn';
    await bid.save();

    res.json({ message: 'Bid withdrawn successfully' });
  } catch (error) {
    console.error('Delete bid error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '0.0.0.0';

app.listen(PORT, HOST, () => {
  console.log(`🚀 Server running on ${HOST}:${PORT}`);
  console.log(`📡 Environment: ${process.env.NODE_ENV || 'development'}`);
});

