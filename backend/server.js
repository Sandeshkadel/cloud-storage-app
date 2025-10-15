const express = require('express');
const cors = require('cors');
const multer = require('multer');
const admin = require('firebase-admin');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Initialize Firebase Admin
const serviceAccount = {
  type: "service_account",
  project_id: "cloud-storage-project-304c0",
  private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
  private_key: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
  client_email: process.env.FIREBASE_CLIENT_EMAIL,
  client_id: process.env.FIREBASE_CLIENT_ID,
  auth_uri: "https://accounts.google.com/o/oauth2/auth",
  token_uri: "https://oauth2.googleapis.com/token",
  auth_provider_x509_cert_url: "https://www.googleapis.com/oauth2/v1/certs",
  client_x509_cert_url: process.env.FIREBASE_CLIENT_CERT_URL
};

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  storageBucket: "cloud-storage-project-304c0.firebasestorage.app"
});

const db = admin.firestore();
const bucket = admin.storage().bucket();

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Multer configuration for file uploads
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 1024 * 1024 * 1024 // 1GB limit
  }
});

// Mock user database (in production, use Firestore)
const users = new Map();

// Auth middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// Routes

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Signup
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password required' });
    }

    if (users.has(email)) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = {
      id: Date.now().toString(),
      email,
      password: hashedPassword,
      storageUsed: 0,
      storageLimit: 15 * 1024 * 1024 * 1024, // 15GB
      createdAt: new Date()
    };

    users.set(email, user);

    const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET);
    
    res.json({
      message: 'User created successfully',
      user: { id: user.id, email: user.email, storageUsed: user.storageUsed },
      token
    });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password required' });
    }

    const user = users.get(email);
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET);
    
    res.json({
      message: 'Login successful',
      user: { id: user.id, email: user.email, storageUsed: user.storageUsed },
      token
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Forgot Password
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ message: 'Email required' });
    }

    const user = users.get(email);
    if (!user) {
      return res.status(400).json({ message: 'User not found' });
    }

    // In production, send actual email
    res.json({ message: 'Password reset email sent' });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Get current user
app.get('/api/auth/me', authenticateToken, (req, res) => {
  const user = users.get(req.user.email);
  if (!user) {
    return res.status(404).json({ message: 'User not found' });
  }

  res.json({ id: user.id, email: user.email, storageUsed: user.storageUsed });
});

// File upload
app.post('/api/files/upload', authenticateToken, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: 'No file uploaded' });
    }

    const user = users.get(req.user.email);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Check storage quota
    if (user.storageUsed + req.file.size > user.storageLimit) {
      return res.status(400).json({ message: 'Storage quota exceeded' });
    }

    const fileName = `users/${req.user.userId}/files/${Date.now()}_${req.file.originalname}`;
    const file = bucket.file(fileName);

    await file.save(req.file.buffer, {
      metadata: {
        contentType: req.file.mimetype,
        metadata: {
          userId: req.user.userId,
          originalName: req.file.originalname,
          size: req.file.size,
          uploadedAt: new Date().toISOString()
        }
      }
    });

    // Make file publicly accessible
    await file.makePublic();

    // Update user storage
    user.storageUsed += req.file.size;
    users.set(req.user.email, user);

    const fileUrl = `https://storage.googleapis.com/${bucket.name}/${fileName}`;

    res.json({
      message: 'File uploaded successfully',
      file: {
        name: req.file.originalname,
        size: req.file.size,
        type: req.file.mimetype,
        url: fileUrl,
        uploadedAt: new Date().toISOString()
      }
    });
  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({ message: 'File upload failed' });
  }
});

// Get user files
app.get('/api/files', authenticateToken, async (req, res) => {
  try {
    const [files] = await bucket.getFiles({
      prefix: `users/${req.user.userId}/files/`
    });

    const fileList = files.map(file => ({
      name: file.name.split('/').pop(),
      size: file.metadata.size,
      type: file.metadata.contentType,
      url: `https://storage.googleapis.com/${bucket.name}/${file.name}`,
      uploadedAt: file.metadata.timeCreated
    }));

    res.json({ files: fileList });
  } catch (error) {
    console.error('Get files error:', error);
    res.status(500).json({ message: 'Failed to get files' });
  }
});

// Delete file
app.delete('/api/files/:fileName', authenticateToken, async (req, res) => {
  try {
    const fileName = `users/${req.user.userId}/files/${req.params.fileName}`;
    const file = bucket.file(fileName);

    const [metadata] = await file.getMetadata();
    await file.delete();

    // Update user storage
    const user = users.get(req.user.email);
    user.storageUsed -= parseInt(metadata.size);
    users.set(req.user.email, user);

    res.json({ message: 'File deleted successfully' });
  } catch (error) {
    console.error('Delete file error:', error);
    res.status(500).json({ message: 'Failed to delete file' });
  }
});

// Get storage info
app.get('/api/storage', authenticateToken, (req, res) => {
  const user = users.get(req.user.email);
  if (!user) {
    return res.status(404).json({ message: 'User not found' });
  }

  res.json({
    used: user.storageUsed,
    limit: user.storageLimit,
    percentage: (user.storageUsed / user.storageLimit) * 100
  });
});

// Serve frontend
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
