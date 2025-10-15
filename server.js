const express = require('express');
const cors = require('cors');
const multer = require('multer');
const admin = require('firebase-admin');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const path = require('path');

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('.')); // Serve static files from current directory

// Initialize Firebase Admin with environment variables
const serviceAccount = {
  type: "service_account",
  project_id: process.env.FIREBASE_PROJECT_ID || "cloud-storage-project-304c0",
  private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
  private_key: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
  client_email: process.env.FIREBASE_CLIENT_EMAIL,
  client_id: process.env.FIREBASE_CLIENT_ID,
  auth_uri: "https://accounts.google.com/o/oauth2/auth",
  token_uri: "https://oauth2.googleapis.com/token",
  auth_provider_x509_cert_url: "https://www.googleapis.com/oauth2/v1/certs",
  client_x509_cert_url: process.env.FIREBASE_CLIENT_CERT_URL
};

try {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    storageBucket: process.env.FIREBASE_STORAGE_BUCKET || "cloud-storage-project-304c0.firebasestorage.app"
  });
  console.log('Firebase Admin initialized successfully');
} catch (error) {
  console.log('Firebase Admin already initialized or error:', error.message);
}

const db = admin.firestore();
const bucket = admin.storage().bucket();

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'cloud-storage-secret-key-2024';

// Email configuration (using Gmail)
const emailTransporter = nodemailer.createTransporter({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER || 'your-email@gmail.com',
    pass: process.env.EMAIL_PASSWORD || 'your-app-password'
  }
});

// Multer configuration for file uploads
const storage = multer.memoryStorage();
const upload = multer({
  storage: storage,
  limits: {
    fileSize: 1024 * 1024 * 1024 // 1GB limit
  },
  fileFilter: (req, file, cb) => {
    // Accept all file types
    cb(null, true);
  }
});

// In-memory storage for demo (in production, use Firestore)
const users = new Map();
const files = new Map();
const folders = new Map();

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

// Admin middleware
const requireAdmin = (req, res, next) => {
  const user = users.get(req.user.email);
  if (!user || !user.isAdmin) {
    return res.status(403).json({ message: 'Admin access required' });
  }
  next();
};

// Utility functions
function generateSecurePassword(length = 12) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
  let password = '';
  for (let i = 0; i < length; i++) {
    password += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return password;
}

function generateId() {
  return Date.now().toString() + Math.random().toString(36).substr(2, 9);
}

// Routes

// Health check
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    service: 'Cloud Storage API'
  });
});

// Signup
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password required' });
    }

    // Basic email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ message: 'Invalid email format' });
    }

    if (users.has(email)) {
      return res.status(400).json({ message: 'User already exists' });
    }

    if (password.length < 6) {
      return res.status(400).json({ message: 'Password must be at least 6 characters' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const userId = generateId();
    
    const user = {
      id: userId,
      email,
      password: hashedPassword,
      storageUsed: 0,
      storageLimit: 15 * 1024 * 1024 * 1024, // 15GB
      isAdmin: users.size === 0, // First user is admin
      createdAt: new Date().toISOString(),
      lastLogin: new Date().toISOString()
    };

    users.set(email, user);

    // Create default folder for user
    const defaultFolder = {
      id: 'root_' + userId,
      userId: userId,
      name: 'My Files',
      createdAt: new Date().toISOString(),
      isDefault: true
    };
    folders.set(defaultFolder.id, defaultFolder);

    const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET);
    
    console.log(`New user registered: ${email}`);
    
    res.json({
      message: 'User created successfully',
      user: { 
        id: user.id, 
        email: user.email, 
        storageUsed: user.storageUsed,
        isAdmin: user.isAdmin 
      },
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

    // Update last login
    user.lastLogin = new Date().toISOString();
    users.set(email, user);

    const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET);
    
    console.log(`User logged in: ${email}`);
    
    res.json({
      message: 'Login successful',
      user: { 
        id: user.id, 
        email: user.email, 
        storageUsed: user.storageUsed,
        isAdmin: user.isAdmin 
      },
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
      // Don't reveal whether user exists for security
      return res.json({ message: 'If the email exists, a password reset link has been sent' });
    }

    // Generate new password
    const newPassword = generateSecurePassword();
    user.password = await bcrypt.hash(newPassword, 10);
    users.set(email, user);

    // Send email with new password
    try {
      const mailOptions = {
        from: process.env.EMAIL_USER || 'noreply@cloudstorage.com',
        to: email,
        subject: 'Your New CloudDrive Password',
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 10px;">
            <div style="text-align: center; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; border-radius: 10px 10px 0 0; color: white;">
              <h1 style="margin: 0;">CloudDrive</h1>
              <p style="margin: 5px 0 0 0; opacity: 0.9;">Secure Cloud Storage</p>
            </div>
            <div style="padding: 30px 20px;">
              <h2 style="color: #333; text-align: center;">Password Reset</h2>
              <p style="color: #666; line-height: 1.6;">Your password has been reset successfully. Here is your new password:</p>
              <div style="background: #f8f9fa; padding: 15px; border-radius: 8px; text-align: center; margin: 20px 0; border: 2px dashed #ddd;">
                <code style="font-size: 18px; font-weight: bold; color: #e83e8c; letter-spacing: 1px;">${newPassword}</code>
              </div>
              <p style="color: #666; line-height: 1.6;">
                Please log in with this new password and consider changing it immediately for security reasons.
              </p>
              <div style="text-align: center; margin-top: 30px;">
                <a href="${process.env.APP_URL || 'https://your-app.onrender.com'}" 
                   style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 12px 30px; text-decoration: none; border-radius: 25px; display: inline-block; font-weight: bold;">
                  Login to CloudDrive
                </a>
              </div>
            </div>
            <div style="text-align: center; padding: 20px; color: #999; font-size: 12px; border-top: 1px solid #e0e0e0;">
              <p>If you didn't request this reset, please contact support immediately.</p>
              <p>&copy; 2024 CloudDrive. All rights reserved.</p>
            </div>
          </div>
        `
      };

      await emailTransporter.sendMail(mailOptions);
      console.log(`Password reset email sent to: ${email}`);
      
      res.json({ message: 'New password has been sent to your email' });
    } catch (emailError) {
      console.error('Email sending error:', emailError);
      res.status(500).json({ message: 'Error sending email. Please try again later.' });
    }
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ message: 'Error processing password reset' });
  }
});

// Get current user
app.get('/api/auth/me', authenticateToken, (req, res) => {
  const user = users.get(req.user.email);
  if (!user) {
    return res.status(404).json({ message: 'User not found' });
  }

  res.json({ 
    id: user.id, 
    email: user.email, 
    storageUsed: user.storageUsed,
    isAdmin: user.isAdmin 
  });
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

    // Check 1GB file size limit
    if (req.file.size > 1024 * 1024 * 1024) {
      return res.status(400).json({ message: 'File size exceeds 1GB limit' });
    }

    // Check if remaining space is less than 1% (153.6 MB)
    const remainingSpace = user.storageLimit - user.storageUsed;
    const threshold = user.storageLimit * 0.01; // 1% threshold
    
    if (remainingSpace - req.file.size < threshold) {
      return res.status(400).json({ 
        message: 'Upload blocked: Less than 1% storage remaining. Please free up space.' 
      });
    }

    const fileId = generateId();
    const fileName = `users/${req.user.userId}/files/${fileId}_${req.file.originalname.replace(/[^a-zA-Z0-9.-]/g, '_')}`;
    
    console.log(`Uploading file: ${fileName}, Size: ${req.file.size} bytes`);

    // Upload to Firebase Storage
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

    // Create file record
    const fileData = {
      id: fileId,
      userId: req.user.userId,
      name: req.file.originalname,
      size: req.file.size,
      type: req.file.mimetype,
      url: fileUrl,
      storagePath: fileName,
      folderId: req.body.folderId || ('root_' + req.user.userId),
      shared: false,
      uploadedAt: new Date().toISOString(),
      downloads: 0
    };

    files.set(fileId, fileData);

    console.log(`File uploaded successfully: ${req.file.originalname} by ${req.user.email}`);

    res.json({
      message: 'File uploaded successfully',
      file: fileData
    });
  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({ message: 'File upload failed: ' + error.message });
  }
});

// Get user files
app.get('/api/files', authenticateToken, (req, res) => {
  try {
    const userFiles = Array.from(files.values())
      .filter(file => file.userId === req.user.userId)
      .map(file => ({
        ...file,
        // Don't include buffer in response
        buffer: undefined
      }));
    
    res.json({ 
      files: userFiles,
      totalCount: userFiles.length,
      totalSize: userFiles.reduce((sum, file) => sum + file.size, 0)
    });
  } catch (error) {
    console.error('Get files error:', error);
    res.status(500).json({ message: 'Failed to get files' });
  }
});

// Get user folders
app.get('/api/folders', authenticateToken, (req, res) => {
  try {
    const userFolders = Array.from(folders.values())
      .filter(folder => folder.userId === req.user.userId);
    
    res.json({ 
      folders: userFolders,
      totalCount: userFolders.length
    });
  } catch (error) {
    console.error('Get folders error:', error);
    res.status(500).json({ message: 'Failed to get folders' });
  }
});

// Create folder
app.post('/api/folders', authenticateToken, async (req, res) => {
  try {
    const { name } = req.body;

    if (!name || name.trim().length === 0) {
      return res.status(400).json({ message: 'Folder name is required' });
    }

    if (name.length > 50) {
      return res.status(400).json({ message: 'Folder name too long (max 50 characters)' });
    }

    const folderId = generateId();
    const folder = {
      id: folderId,
      userId: req.user.userId,
      name: name.trim(),
      createdAt: new Date().toISOString(),
      fileCount: 0
    };

    folders.set(folderId, folder);

    console.log(`Folder created: ${name} by ${req.user.email}`);

    res.json({
      message: 'Folder created successfully',
      folder
    });
  } catch (error) {
    console.error('Create folder error:', error);
    res.status(500).json({ message: 'Failed to create folder' });
  }
});

// Download file
app.get('/api/files/download/:fileId', authenticateToken, async (req, res) => {
  try {
    const file = files.get(req.params.fileId);
    
    if (!file || file.userId !== req.user.userId) {
      return res.status(404).json({ message: 'File not found' });
    }

    const fileRef = bucket.file(file.storagePath);

    const [exists] = await fileRef.exists();
    if (!exists) {
      return res.status(404).json({ message: 'File not found in storage' });
    }

    // Update download count
    file.downloads = (file.downloads || 0) + 1;
    files.set(req.params.fileId, file);

    const [metadata] = await fileRef.getMetadata();
    
    res.setHeader('Content-Type', metadata.contentType);
    res.setHeader('Content-Disposition', `attachment; filename="${file.name}"`);
    res.setHeader('Content-Length', metadata.size);

    console.log(`File downloaded: ${file.name} by ${req.user.email}`);

    fileRef.createReadStream()
      .pipe(res)
      .on('error', (error) => {
        console.error('Download stream error:', error);
        res.status(500).json({ message: 'Download failed' });
      });
  } catch (error) {
    console.error('Download error:', error);
    res.status(500).json({ message: 'Download failed' });
  }
});

// Share file
app.post('/api/files/share/:fileId', authenticateToken, async (req, res) => {
  try {
    const file = files.get(req.params.fileId);
    
    if (!file || file.userId !== req.user.userId) {
      return res.status(404).json({ message: 'File not found' });
    }

    file.shared = true;
    file.shareUrl = `${req.protocol}://${req.get('host')}/api/files/shared/${req.params.fileId}`;
    file.sharedAt = new Date().toISOString();
    files.set(req.params.fileId, file);

    console.log(`File shared: ${file.name} by ${req.user.email}`);

    res.json({
      message: 'File shared successfully',
      shareUrl: file.shareUrl
    });
  } catch (error) {
    console.error('Share error:', error);
    res.status(500).json({ message: 'Sharing failed' });
  }
});

// Delete file
app.delete('/api/files/:fileId', authenticateToken, async (req, res) => {
  try {
    const file = files.get(req.params.fileId);
    
    if (!file || file.userId !== req.user.userId) {
      return res.status(404).json({ message: 'File not found' });
    }

    // Delete from storage
    try {
      await bucket.file(file.storagePath).delete();
    } catch (storageError) {
      console.warn('File not found in storage, but removing from records:', storageError.message);
    }

    // Update user storage
    const user = users.get(req.user.email);
    user.storageUsed -= file.size;
    users.set(req.user.email, user);

    // Delete file record
    files.delete(req.params.fileId);

    console.log(`File deleted: ${file.name} by ${req.user.email}`);

    res.json({ 
      message: 'File deleted successfully',
      storageFreed: file.size
    });
  } catch (error) {
    console.error('Delete error:', error);
    res.status(500).json({ message: 'Delete failed' });
  }
});

// Move file to folder
app.put('/api/files/:fileId/move', authenticateToken, async (req, res) => {
  try {
    const { folderId } = req.body;
    const file = files.get(req.params.fileId);
    
    if (!file || file.userId !== req.user.userId) {
      return res.status(404).json({ message: 'File not found' });
    }

    // Validate folder exists and belongs to user
    if (folderId !== ('root_' + req.user.userId) && !folders.has(folderId)) {
      return res.status(404).json({ message: 'Folder not found' });
    }

    const oldFolderId = file.folderId;
    file.folderId = folderId;
    file.movedAt = new Date().toISOString();
    files.set(req.params.fileId, file);

    console.log(`File moved: ${file.name} from ${oldFolderId} to ${folderId} by ${req.user.email}`);

    res.json({ 
      message: 'File moved successfully',
      oldFolder: oldFolderId,
      newFolder: folderId
    });
  } catch (error) {
    console.error('Move error:', error);
    res.status(500).json({ message: 'Move failed' });
  }
});

// Get storage info
app.get('/api/storage', authenticateToken, (req, res) => {
  try {
    const user = users.get(req.user.email);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const userFiles = Array.from(files.values()).filter(file => file.userId === req.user.userId);
    const totalSize = userFiles.reduce((sum, file) => sum + file.size, 0);
    
    // Verify consistency
    if (user.storageUsed !== totalSize) {
      console.warn(`Storage inconsistency for user ${req.user.email}: recorded ${user.storageUsed} vs actual ${totalSize}`);
      user.storageUsed = totalSize;
      users.set(req.user.email, user);
    }

    res.json({
      used: user.storageUsed,
      limit: user.storageLimit,
      percentage: (user.storageUsed / user.storageLimit) * 100,
      remaining: user.storageLimit - user.storageUsed,
      fileCount: userFiles.length,
      warning: (user.storageUsed / user.storageLimit) > 0.9 ? 'low' : 'normal'
    });
  } catch (error) {
    console.error('Storage info error:', error);
    res.status(500).json({ message: 'Failed to get storage info' });
  }
});

// Admin - Get all users
app.get('/api/admin/users', authenticateToken, requireAdmin, (req, res) => {
  try {
    const allUsers = Array.from(users.values()).map(user => ({
      id: user.id,
      email: user.email,
      storageUsed: user.storageUsed,
      storageLimit: user.storageLimit,
      isAdmin: user.isAdmin,
      createdAt: user.createdAt,
      lastLogin: user.lastLogin,
      fileCount: Array.from(files.values()).filter(f => f.userId === user.id).length
    }));
    
    res.json({ 
      users: allUsers,
      totalUsers: allUsers.length,
      totalStorageUsed: allUsers.reduce((sum, user) => sum + user.storageUsed, 0)
    });
  } catch (error) {
    console.error('Admin users error:', error);
    res.status(500).json({ message: 'Failed to get users' });
  }
});

// Admin - Get all files
app.get('/api/admin/files', authenticateToken, requireAdmin, (req, res) => {
  try {
    const allFiles = Array.from(files.values()).map(file => ({
      ...file,
      userEmail: users.get(Array.from(users.values()).find(u => u.id === file.userId)?.email)?.email || 'Unknown'
    }));
    
    res.json({ 
      files: allFiles,
      totalFiles: allFiles.length,
      totalSize: allFiles.reduce((sum, file) => sum + file.size, 0)
    });
  } catch (error) {
    console.error('Admin files error:', error);
    res.status(500).json({ message: 'Failed to get files' });
  }
});

// Serve frontend for all other routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({ 
    message: 'Internal server error',
    error: process.env.NODE_ENV === 'production' ? {} : error.message 
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ message: 'Route not found' });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, '0.0.0.0', () => {
  console.log(`
  🚀 Cloud Storage App Server Started!
  
  📍 Port: ${PORT}
  🌐 Environment: ${process.env.NODE_ENV || 'development'}
  🔐 Firebase Project: ${serviceAccount.project_id}
  💾 Storage Bucket: ${bucket.name}
  
  ✅ Health Check: http://localhost:${PORT}/api/health
  📧 Email Service: ${process.env.EMAIL_USER ? 'Configured' : 'Not configured'}
  
  Server is ready to accept requests...
  `);
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\n🛑 Server shutting down gracefully...');
  process.exit(0);
});

process.on('SIGTERM', () => {
  console.log('\n🛑 Server shutting down gracefully...');
  process.exit(0);
});
