
const express = require('express');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const moment = require('moment');

const app = express();

// Middleware
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
  secret: 'sarker-wifi-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false }
}));

// Set view engine
app.set('view engine', 'ejs');
app.set('views', './views');

// File upload configuration
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const dir = './public/uploads/';
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    cb(null, dir);
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + '-' + file.originalname);
  }
});

const upload = multer({ 
  storage: storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
  fileFilter: function (req, file, cb) {
    if (file.mimetype.startsWith('image/') || file.mimetype === 'application/pdf') {
      cb(null, true);
    } else {
      cb(new Error('Only images and PDFs are allowed'));
    }
  }
});

// In-memory data storage (in production, use a proper database)
let users = [];
let registrationRequests = [];
let complaints = [];
let notifications = [];
let invoices = [];
let paymentRecords = [];

// Admin credentials
const ADMIN = {
  userId: '697013',
  mobile: '01324309754',
  password: 'SarkerUtsab'
};

// Helper functions
function generateUserId() {
  return Math.random().toString(36).substr(2, 9);
}

function isLoggedIn(req, res, next) {
  if (req.session.user) {
    next();
  } else {
    res.redirect('/');
  }
}

function isAdmin(req, res, next) {
  if (req.session.user && req.session.user.isAdmin) {
    next();
  } else {
    res.redirect('/');
  }
}

// Routes
app.get('/', (req, res) => {
  res.render('index', { user: req.session.user });
});

app.get('/register', (req, res) => {
  res.render('register', { error: null });
});

app.post('/register', async (req, res) => {
  const {
    name, mobile, email, dob, block, roomNumber, deviceCount,
    deviceType, password, confirmPassword
  } = req.body;

  if (password !== confirmPassword) {
    return res.render('register', { error: 'Passwords do not match' });
  }

  // Check if mobile already exists
  const existingUser = users.find(u => u.mobile === mobile) || 
                      registrationRequests.find(r => r.mobile === mobile);
  
  if (existingUser) {
    return res.render('register', { error: 'Mobile number already registered' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const roomCode = `${block} ${roomNumber.padStart(2, '0')}`;

  const registrationRequest = {
    id: generateUserId(),
    name,
    mobile,
    email,
    dob,
    roomCode,
    deviceCount: parseInt(deviceCount),
    deviceType,
    password: hashedPassword,
    requestDate: new Date(),
    status: 'pending'
  };

  registrationRequests.push(registrationRequest);
  res.render('registration-success');
});

app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

app.post('/login', async (req, res) => {
  const { mobile, password } = req.body;

  // Check user login only
  const user = users.find(u => u.mobile === mobile);
  if (user && await bcrypt.compare(password, user.password)) {
    req.session.user = {
      id: user.id,
      mobile: user.mobile,
      isAdmin: false,
      name: user.name
    };
    return res.redirect('/user/dashboard');
  }

  res.render('login', { error: 'Invalid mobile number or password' });
});

// Admin login routes
app.get('/admin/login', (req, res) => {
  res.render('admin-login', { error: null });
});

app.post('/admin/login', async (req, res) => {
  const { userId, mobile, password } = req.body;

  // Check admin credentials - all three fields must match
  if (userId === ADMIN.userId && mobile === ADMIN.mobile && password === ADMIN.password) {
    req.session.user = {
      id: ADMIN.userId,
      mobile: ADMIN.mobile,
      isAdmin: true,
      name: 'Admin'
    };
    return res.redirect('/admin/dashboard');
  }

  res.render('admin-login', { error: 'Invalid User ID, mobile number, or password' });
});

app.get('/forgot-password', (req, res) => {
  res.render('forgot-password', { error: null, success: null });
});

app.post('/forgot-password', async (req, res) => {
  const { mobile, email, dob } = req.body;
  
  const user = users.find(u => 
    u.mobile === mobile && 
    u.email === email && 
    u.dob === dob
  );

  if (user) {
    // Generate a temporary password
    const tempPassword = Math.random().toString(36).slice(-8);
    const hashedTempPassword = await bcrypt.hash(tempPassword, 10);
    
    // Update user's password
    user.password = hashedTempPassword;
    
    res.render('forgot-password', { 
      error: null, 
      success: true,
      userData: {
        name: user.name,
        mobile: user.mobile,
        password: tempPassword
      }
    });
  } else {
    res.render('forgot-password', { 
      error: 'Information does not match our records',
      success: null 
    });
  }
});

// Helper function to check and update account status based on connection deadline
function updateAccountStatus(user) {
  if (user.connectionEndDate) {
    const now = moment();
    const endDate = moment(user.connectionEndDate);
    
    if (now.isAfter(endDate)) {
      user.accountStatus = 'deactivated';
    } else if (user.accountStatus === 'deactivated' && now.isBefore(endDate)) {
      // Reactivate if within valid period and was manually deactivated
      user.accountStatus = 'active';
    }
  }
}

// User dashboard routes
app.get('/user/dashboard', isLoggedIn, (req, res) => {
  const user = users.find(u => u.id === req.session.user.id);
  
  // Update account status based on connection deadline
  updateAccountStatus(user);
  
  const userNotifications = notifications.filter(n => n.userId === user.id);
  const userInvoices = invoices.filter(i => i.userId === user.id);
  const userComplaints = complaints.filter(c => c.userId === user.id);
  
  // Check for payment reminders
  if (user.connectionEndDate) {
    const daysUntilEnd = moment(user.connectionEndDate).diff(moment(), 'days');
    if (daysUntilEnd <= 7 && daysUntilEnd > 0) {
      const reminderExists = userNotifications.find(n => 
        n.type === 'payment_reminder' && 
        moment(n.date).isSame(moment(), 'day')
      );
      
      if (!reminderExists) {
        notifications.push({
          id: generateUserId(),
          userId: user.id,
          type: 'payment_reminder',
          message: `Payment due in ${daysUntilEnd} days. Please pay before ${moment(user.connectionEndDate).format('DD/MM/YYYY')}`,
          date: new Date(),
          read: false
        });
      }
    }
  }

  res.render('user-dashboard', { 
    user, 
    notifications: userNotifications.filter(n => !n.read),
    invoices: userInvoices,
    complaints: userComplaints,
    paymentRecords
  });
});

app.post('/user/upload-photo', isLoggedIn, upload.single('photo'), (req, res) => {
  const user = users.find(u => u.id === req.session.user.id);
  if (user && req.file) {
    user.photo = '/uploads/' + req.file.filename;
  }
  res.redirect('/user/dashboard');
});

app.post('/user/complaint', isLoggedIn, (req, res) => {
  const { subject, description } = req.body;
  const complaint = {
    id: generateUserId(),
    userId: req.session.user.id,
    subject,
    description,
    date: new Date(),
    status: 'pending',
    response: null
  };
  
  complaints.push(complaint);
  res.redirect('/user/dashboard');
});

app.post('/user/mark-notification-read/:id', isLoggedIn, (req, res) => {
  const notification = notifications.find(n => n.id === req.params.id);
  if (notification) {
    notification.read = true;
  }
  res.json({ success: true });
});

app.post('/user/upload-payment', isLoggedIn, upload.single('paymentFile'), (req, res) => {
  const { description, amount, paymentDate } = req.body;
  
  const paymentRecord = {
    id: generateUserId(),
    userId: req.session.user.id,
    description,
    amount: parseFloat(amount),
    paymentDate,
    filePath: req.file ? '/uploads/' + req.file.filename : null,
    uploadDate: new Date(),
    status: 'pending_verification'
  };
  
  paymentRecords.push(paymentRecord);
  
  // Send notification to admin
  notifications.push({
    id: generateUserId(),
    userId: 'admin',
    type: 'payment_upload',
    message: `New payment information uploaded by ${req.session.user.name} (${req.session.user.mobile})`,
    date: new Date(),
    read: false
  });
  
  res.redirect('/user/dashboard');
});

// Admin dashboard routes
app.get('/admin/dashboard', isAdmin, (req, res) => {
  // Update all users' account status based on connection deadline
  users.forEach(user => updateAccountStatus(user));
  
  const pendingRequests = registrationRequests.filter(r => r.status === 'pending');
  const pendingComplaints = complaints.filter(c => c.status === 'pending');
  
  res.render('admin-dashboard', { 
    users, 
    pendingRequests,
    pendingComplaints,
    paymentRecords,
    totalUsers: users.length,
    totalRevenue: users.reduce((sum, u) => sum + (u.monthlyAmount || 0), 0)
  });
});

app.post('/admin/approve-registration/:id', isAdmin, (req, res) => {
  const request = registrationRequests.find(r => r.id === req.params.id);
  if (request) {
    const newUser = {
      id: generateUserId(),
      name: request.name,
      mobile: request.mobile,
      email: request.email,
      dob: request.dob,
      roomCode: request.roomCode,
      deviceCount: request.deviceCount,
      deviceType: request.deviceType,
      password: request.password,
      photo: null,
      devices: [],
      monthlyAmount: 0,
      connectionStartDate: null,
      connectionEndDate: null,
      status: 'active',
      accountStatus: 'active',
      joinDate: new Date()
    };
    
    users.push(newUser);
    request.status = 'approved';
  }
  res.redirect('/admin/dashboard');
});

app.post('/admin/reject-registration/:id', isAdmin, (req, res) => {
  const request = registrationRequests.find(r => r.id === req.params.id);
  if (request) {
    request.status = 'rejected';
  }
  res.redirect('/admin/dashboard');
});

app.get('/admin/user/:id', isAdmin, (req, res) => {
  const user = users.find(u => u.id === req.params.id);
  const userInvoices = invoices.filter(i => i.userId === user.id);
  res.render('admin-user-details', { user, invoices: userInvoices, notifications });
});

app.post('/admin/update-user/:id', isAdmin, (req, res) => {
  const user = users.find(u => u.id === req.params.id);
  if (user) {
    const { monthlyAmount, connectionStartDate, connectionEndDate, deviceInfo } = req.body;
    
    user.monthlyAmount = parseFloat(monthlyAmount) || 0;
    user.connectionStartDate = connectionStartDate || null;
    user.connectionEndDate = connectionEndDate || null;
    
    if (deviceInfo) {
      try {
        user.devices = JSON.parse(deviceInfo);
      } catch (e) {
        console.error('Error parsing device info:', e);
      }
    }
  }
  res.redirect(`/admin/user/${req.params.id}`);
});

app.post('/admin/upload-invoice/:id', isAdmin, upload.single('invoice'), (req, res) => {
  const { month, year, amount, deviceCount } = req.body;
  
  const invoice = {
    id: generateUserId(),
    userId: req.params.id,
    month,
    year,
    amount: parseFloat(amount),
    deviceCount: parseInt(deviceCount),
    filePath: req.file ? '/uploads/' + req.file.filename : null,
    uploadDate: new Date(),
    paid: false
  };
  
  invoices.push(invoice);
  res.redirect(`/admin/user/${req.params.id}`);
});

app.post('/admin/mark-payment/:invoiceId', isAdmin, (req, res) => {
  const { paid } = req.body;
  const invoice = invoices.find(i => i.id === req.params.invoiceId);
  if (invoice) {
    invoice.paid = paid === 'true';
  }
  const referer = req.get('Referer') || '/admin/dashboard';
  res.redirect(referer);
});

app.post('/admin/send-notification', isAdmin, (req, res) => {
  const { userId, message, type } = req.body;
  
  if (userId === 'all') {
    users.forEach(user => {
      notifications.push({
        id: generateUserId(),
        userId: user.id,
        type: type || 'admin',
        message,
        date: new Date(),
        read: false
      });
    });
  } else {
    notifications.push({
      id: generateUserId(),
      userId,
      type: type || 'admin',
      message,
      date: new Date(),
      read: false
    });
  }
  
  res.redirect('/admin/dashboard');
});

app.post('/admin/resolve-complaint/:id', isAdmin, (req, res) => {
  const { status, response } = req.body;
  const complaint = complaints.find(c => c.id === req.params.id);
  
  if (complaint) {
    complaint.status = status;
    complaint.response = response;
    complaint.resolvedDate = new Date();
    
    // Send notification to user
    notifications.push({
      id: generateUserId(),
      userId: complaint.userId,
      type: 'complaint_response',
      message: `Your complaint "${complaint.subject}" has been ${status}. Response: ${response}`,
      date: new Date(),
      read: false
    });
  }
  
  res.redirect('/admin/dashboard');
});

// Update account status
app.post('/admin/update-account-status/:id', isAdmin, (req, res) => {
  const user = users.find(u => u.id === req.params.id);
  if (user) {
    user.accountStatus = req.body.accountStatus;
  }
  res.redirect('/admin/dashboard');
});

// Delete user
app.post('/admin/delete-user/:id', isAdmin, (req, res) => {
  const userId = req.params.id;
  
  // Remove user from users array
  users = users.filter(u => u.id !== userId);
  
  // Remove user's invoices
  invoices = invoices.filter(i => i.userId !== userId);
  
  // Remove user's complaints
  complaints = complaints.filter(c => c.userId !== userId);
  
  // Remove user's notifications
  notifications = notifications.filter(n => n.userId !== userId);
  
  res.redirect('/admin/dashboard');
});

// Edit user registration information
app.post('/admin/edit-user-info/:id', isAdmin, (req, res) => {
  const user = users.find(u => u.id === req.params.id);
  if (user) {
    const { name, mobile, email, dob, block, roomNumber, deviceCount, deviceType } = req.body;
    
    // Check if mobile number already exists for another user
    const existingUser = users.find(u => u.mobile === mobile && u.id !== req.params.id);
    if (existingUser) {
      return res.redirect(`/admin/user/${req.params.id}?error=mobile_exists`);
    }
    
    user.name = name;
    user.mobile = mobile;
    user.email = email;
    user.dob = dob;
    user.roomCode = `${block} ${roomNumber.toString().padStart(2, '0')}`;
    user.deviceCount = parseInt(deviceCount);
    user.deviceType = deviceType;
  }
  res.redirect(`/admin/user/${req.params.id}`);
});

// Delete invoice
app.post('/admin/delete-invoice/:invoiceId', isAdmin, (req, res) => {
  const invoice = invoices.find(i => i.id === req.params.invoiceId);
  if (invoice) {
    // Delete the PDF file if it exists
    if (invoice.filePath) {
      const filePath = './public' + invoice.filePath;
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
      }
    }
    
    // Remove invoice from array
    invoices = invoices.filter(i => i.id !== req.params.invoiceId);
  }
  res.redirect('back');
});

// Edit invoice information
app.post('/admin/edit-invoice/:invoiceId', isAdmin, (req, res) => {
  const { month, year, amount, deviceCount } = req.body;
  const invoice = invoices.find(i => i.id === req.params.invoiceId);
  
  if (invoice) {
    invoice.month = month;
    invoice.year = year;
    invoice.amount = parseFloat(amount);
    invoice.deviceCount = parseInt(deviceCount);
  }
  
  const referer = req.get('Referer') || '/admin/dashboard';
  res.redirect(referer);
});

// Payment verification route
app.post('/admin/verify-payment/:paymentId', isAdmin, (req, res) => {
  const { status } = req.body;
  const payment = paymentRecords.find(p => p.id === req.params.paymentId);
  
  if (payment) {
    payment.status = status;
    payment.verificationDate = new Date();
    
    // Send notification to user
    const user = users.find(u => u.id === payment.userId);
    if (user) {
      const statusText = status === 'verified' ? 'approved' : 'rejected';
      notifications.push({
        id: generateUserId(),
        userId: payment.userId,
        type: 'payment_verification',
        message: `Your payment information for ৳${payment.amount} has been ${statusText} by admin.`,
        date: new Date(),
        read: false
      });
    }
  }
  
  res.redirect('/admin/dashboard');
});

// Replace invoice PDF
app.post('/admin/replace-invoice-pdf/:invoiceId', isAdmin, upload.single('newInvoice'), (req, res) => {
  const invoice = invoices.find(i => i.id === req.params.invoiceId);
  
  if (invoice && req.file) {
    // Delete old PDF file if it exists
    if (invoice.filePath) {
      const oldFilePath = './public' + invoice.filePath;
      if (fs.existsSync(oldFilePath)) {
        fs.unlinkSync(oldFilePath);
      }
    }
    
    // Update with new file path
    invoice.filePath = '/uploads/' + req.file.filename;
  }
  
  const referer = req.get('Referer') || '/admin/dashboard';
  res.redirect(referer);
});

// Admin notification management routes
app.post('/admin/add-user-notification/:userId', isAdmin, (req, res) => {
  const { subject, message } = req.body;
  const userId = req.params.userId;
  
  notifications.push({
    id: generateUserId(),
    userId: userId,
    type: 'admin_notification',
    subject: subject,
    message: message,
    date: new Date(),
    read: false
  });
  
  const referer = req.get('Referer') || '/admin/dashboard';
  res.redirect(referer);
});

app.post('/admin/remove-notification/:notificationId', isAdmin, (req, res) => {
  const notificationId = req.params.notificationId;
  notifications = notifications.filter(n => n.id !== notificationId);
  
  const referer = req.get('Referer') || '/admin/dashboard';
  res.redirect(referer);
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Sarker WiFi server running on port ${PORT}`);
});
