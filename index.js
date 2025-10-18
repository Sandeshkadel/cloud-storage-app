const functions = require('firebase-functions');
const admin = require('firebase-admin');
const nodemailer = require('nodemailer');

admin.initializeApp();

// Configure email (using Gmail SMTP)
const transporter = nodemailer.createTransporter({
  service: 'gmail',
  auth: {
    user: functions.config().gmail.email,
    pass: functions.config().gmail.password
  }
});

// Generate secure random password
function generatePassword() {
  const length = 12;
  const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
  let password = "";
  for (let i = 0; i < length; i++) {
    password += charset.charAt(Math.floor(Math.random() * charset.length));
  }
  return password;
}

// Password reset function
exports.resetPassword = functions.https.onCall(async (data, context) => {
  const email = data.email;
  
  try {
    // Generate new password
    const newPassword = generatePassword();
    
    // Update user's password
    const user = await admin.auth().getUserByEmail(email);
    await admin.auth().updateUser(user.uid, {
      password: newPassword
    });
    
    // Send email with new password
    const mailOptions = {
      from: functions.config().gmail.email,
      to: email,
      subject: 'CloudDrive - Your New Password',
      html: `
        <h2>CloudDrive Password Reset</h2>
        <p>Your new temporary password is: <strong>${newPassword}</strong></p>
        <p>Please login and change your password immediately.</p>
        <p><a href="https://your-app-url.com">Login to CloudDrive</a></p>
      `
    };
    
    await transporter.sendMail(mailOptions);
    
    return { success: true, message: 'New password sent to email' };
  } catch (error) {
    throw new functions.https.HttpsError('internal', error.message);
  }
});

// Update storage usage on file upload
exports.updateStorageOnUpload = functions.storage.object().onFinalize(async (object) => {
  const filePath = object.name;
  const fileSize = object.size;
  
  // Extract user ID from file path
  const userId = filePath.split('/')[1];
  
  if (!userId) return null;
  
  try {
    // Update user's storage usage
    await admin.firestore().collection('users').doc(userId).update({
      usedBytes: admin.firestore.FieldValue.increment(fileSize),
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });
    
    return null;
  } catch (error) {
    console.error('Error updating storage:', error);
    return null;
  }
});

// Update storage usage on file delete
exports.updateStorageOnDelete = functions.storage.object().onDelete(async (object) => {
  const filePath = object.name;
  const fileSize = object.size;
  
  // Extract user ID from file path
  const userId = filePath.split('/')[1];
  
  if (!userId) return null;
  
  try {
    // Update user's storage usage
    await admin.firestore().collection('users').doc(userId).update({
      usedBytes: admin.firestore.FieldValue.increment(-fileSize),
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });
    
    return null;
  } catch (error) {
    console.error('Error updating storage:', error);
    return null;
  }
});

// Admin function to get all users
exports.getAdminUsers = functions.https.onCall(async (data, context) => {
  // Check if user is admin
  if (!context.auth || !context.auth.token.admin) {
    throw new functions.https.HttpsError('permission-denied', 'Admin access required');
  }
  
  try {
    const usersSnapshot = await admin.firestore().collection('users').get();
    const users = [];
    
    for (const userDoc of usersSnapshot.docs) {
      const userData = userDoc.data();
      const filesSnapshot = await admin.firestore().collection('files')
        .where('userId', '==', userDoc.id)
        .get();
      
      users.push({
        id: userDoc.id,
        email: userData.email,
        usedBytes: userData.usedBytes || 0,
        quotaBytes: userData.quotaBytes || (15 * 1024 * 1024 * 1024),
        fileCount: filesSnapshot.size,
        createdAt: userData.createdAt
      });
    }
    
    return { users };
  } catch (error) {
    throw new functions.https.HttpsError('internal', error.message);
  }
});
