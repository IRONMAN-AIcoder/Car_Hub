// Updated Car Hub Backend — Node.js + Express + MongoDB
// This version auto-maps incoming fields from the current frontend structure without requiring HTML name attributes.

require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const path = require('path');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const User = require('./models/User');
const Order = require('./models/Order');

const SALT_ROUNDS = 10;

const app = express();
app.use(cors());
app.use(express.json());

// Serve static frontend files
app.use(express.static(path.join(__dirname, 'public')));

// --- Auth Routes ---
app.post('/api/auth/signup', async (req, res) => {
  try {
    let { name, email, phone, username, password } = req.body;
    const values = Object.values(req.body);

    if (!name && values.length >= 5) {
      name = values[0];
      email = values[1];
      phone = values[2];
      username = values[3];
      password = values[4];
    }

    if (!name || !email || !username || !password) {
      return res.status(400).json({ message: 'Missing required fields' });
    }

    const existing = await User.findOne({ $or: [{ email }, { username }] });
    if (existing) return res.status(409).json({ message: 'Email or username already in use' });

    const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
    const user = new User({ name, email, phone, username, passwordHash });
    await user.save();

    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ message: 'User created', token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    let { username, password } = req.body;
    const values = Object.values(req.body);

    if (!username && values.length >= 2) {
      username = values[0];
      password = values[1];
    }

    if (!username || !password) return res.status(400).json({ message: 'Missing username or password' });

    const user = await User.findOne({ username });
    if (!user) return res.status(401).json({ message: 'Invalid credentials' });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ message: 'Invalid credentials' });

    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ message: 'Login successful', token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// --- Orders Routes ---
async function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ message: 'Missing auth header' });
  const parts = header.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') return res.status(401).json({ message: 'Invalid auth format' });
  const token = parts[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = await User.findById(payload.id).select('-passwordHash');
    if (!req.user) return res.status(401).json({ message: 'User not found' });
    next();
  } catch (err) {
    res.status(401).json({ message: 'Invalid token' });
  }
}

app.post('/api/orders', auth, async (req, res) => {
  try {
    let { model, color, variant, price } = req.body;
    const values = Object.values(req.body);

    if (!model && values.length > 0) {
      color = color || values[0];
      variant = variant || values[1];
      model = model || 'Unknown Model';
    }

    if (typeof price === 'string') {
      const parsed = parseFloat(price.replace(/[^0-9.]/g, ''));
      if (!isNaN(parsed)) price = parsed;
    }

    if (!model || !price) {
      return res.status(400).json({ message: 'Missing required order fields (model, price)' });
    }

    const order = new Order({ user: req.user._id, model, color, variant, price });
    await order.save();

    res.json({ message: 'Order placed', order });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/orders/my', auth, async (req, res) => {
  try {
    const orders = await Order.find({ user: req.user._id }).sort('-createdAt');
    res.json({ orders });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/orders', async (req, res) => {
  try {
    const orders = await Order.find().populate('user', 'name email username');
    res.json({ orders });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});


const PORT = process.env.PORT || 3001;
async function start() {
  try {
    const mongoUri = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/carhub';
    await mongoose.connect(mongoUri, { useNewUrlParser: true, useUnifiedTopology: true });
    console.log('Connected to MongoDB');
    app.listen(PORT, () => console.log(`Server listening on port ${PORT}`));
  } catch (err) {
    console.error('Failed to start server', err);
    process.exit(1);
  }
}
start();
