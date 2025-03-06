import mongoose from 'mongoose';
import moment from 'moment-timezone';
import NodeCache from 'node-cache';

// Cache setup
export const cache = new NodeCache({ 
  stdTTL: 600,
  checkperiod: 120,
  useClones: false,
  maxKeys: 1000
});

// Format date helper function
export const formatDate = () => {
  const cacheKey = 'currentFormattedDate';
  const cachedDate = cache.get(cacheKey);
  
  if (cachedDate) return cachedDate;
  
  const formattedDate = moment().tz('Asia/Kolkata').format('DD-MMM-YYYY HH:mm:ss IST');
  cache.set(cacheKey, formattedDate, 1);
  return formattedDate;
};

// User schema definition
const UserSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    minlength: 3,
    maxlength: 50
  },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
    match: [/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/, 'Please provide a valid email']
  },
  password: {
    type: String,
    required: true,
    minlength: 6
  },
  deviceToken: {
    type: String,
    required: true
  },
  loginIp: {
    type: String,
    default: null
  },
  lastLoginTime: {
    type: String,
    default: null
  },
  createdAt: {
    type: String,
    default: formatDate
  }
});

UserSchema.index({ deviceToken: 1 });

// Create the User model
export const User = mongoose.model('User', UserSchema);

// Database connection function
export const connectDB = async () => {
  try {
    const mongoOptions = {
      serverSelectionTimeoutMS: 5000,
      maxPoolSize: 10,
      socketTimeoutMS: 45000,
    };
    
    await mongoose.connect(process.env.MONGODB_URI, mongoOptions);
    console.log('MongoDB connected successfully');
  } catch (err) {
    console.error('MongoDB connection error:', err);
    if (process.env.NODE_ENV === 'production') {
      setTimeout(connectDB, 5000);
    }
  }
};