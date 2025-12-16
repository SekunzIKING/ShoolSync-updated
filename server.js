const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(helmet());
const corsOrigin = process.env.CORS_ORIGIN || true;
app.use(cors({ origin: corsOrigin }));

// basic rate limiting
const limiter = rateLimit({ windowMs: 60 * 1000, max: 100, standardHeaders: true, legacyHeaders: false });
app.use(limiter);

const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/kda_demo';
const JWT_SECRET = process.env.JWT_SECRET || 'change_this_secret';
const PORT = process.env.PORT || 4000;

mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(()=> console.log('MongoDB connected'))
  .catch(err=> console.error('Mongo error',err));

// Schemas
const UserSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true, index: true },
  passwordHash: String,
  role: { type: String, enum: ['admin','student'], default: 'student' }
});
const StudentSchema = new mongoose.Schema({
  fullName: String,
  classLevel: String,
  parentPhone: String,
  createdAt: { type: Date, default: Date.now }
});
const BookSchema = new mongoose.Schema({
  title: String,
  author: String,
  isbn: String,
  available: { type: Boolean, default: true }
});
const AttendanceSchema = new mongoose.Schema({
  studentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Student' },
  date: Date,
  status: { type: String, enum: ['present','absent','late'] },
  notes: String
});

const User = mongoose.model('User', UserSchema);
const Student = mongoose.model('Student', StudentSchema);
const Book = mongoose.model('Book', BookSchema);
const Attendance = mongoose.model('Attendance', AttendanceSchema);

// Helpers
function generateToken(user){ return jwt.sign({ id: user._id, role: user.role, email: user.email }, JWT_SECRET, { expiresIn: '8h' }); }
function authMiddleware(req,res,next){
  const header = req.headers.authorization;
  if(!header) return res.status(401).json({ error: 'Authorization required' });
  const token = header.split(' ')[1];
  try { req.user = jwt.verify(token, JWT_SECRET); next(); } catch(e){ return res.status(401).json({ error: 'Invalid token' }); }
}
function roleRequired(role){
  return (req,res,next)=> { if(!req.user) return res.status(401).json({ error:'Auth required' }); if(req.user.role !== role) return res.status(403).json({ error:'Forbidden' }); next(); };
}

// small wrapper to catch async errors
const asyncHandler = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// Routes
app.get('/', (req,res)=> res.json({ ok:true }));

// return current user summary
app.get('/api/me', authMiddleware, asyncHandler(async (req,res)=>{
  const user = await User.findById(req.user.id).select('name email role');
  if (!user) return res.status(404).json({ error: 'Not found' });
  res.json({ user });
}));

// Auth
app.post('/api/auth/register',
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min:6 }),
  body('name').notEmpty().trim().escape(),
  asyncHandler(async (req,res)=>{
    const errors = validationResult(req); if(!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
    const { name, email, password, role } = req.body;
    const normalizedEmail = (email || '').toLowerCase();
    if (await User.findOne({ email: normalizedEmail })) return res.status(400).json({ error: 'Email already used' });
    const passwordHash = await bcrypt.hash(password, 10);
    const user = new User({ name, email: normalizedEmail, passwordHash, role: role || 'student' });
    try {
      await user.save();
    } catch (e) {
      if (e.code === 11000) return res.status(400).json({ error: 'Email already used' });
      throw e;
    }
    const token = generateToken(user);
    res.json({ token, user: { id: user._id, name: user.name, email: user.email, role: user.role } });
  })
);

app.post('/api/auth/login',
  body('email').isEmail().normalizeEmail(),
  body('password').notEmpty(),
  asyncHandler(async (req,res)=>{
    const errors = validationResult(req); if(!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
    const { email, password } = req.body;
    const normalizedEmail = (email || '').toLowerCase();
    const user = await User.findOne({ email: normalizedEmail });
    if(!user) return res.status(400).json({ error: 'Invalid credentials' });
    const ok = await bcrypt.compare(password, user.passwordHash);
    if(!ok) return res.status(400).json({ error: 'Invalid credentials' });
    const token = generateToken(user);
    res.json({ token, user: { id: user._id, name: user.name, email: user.email, role: user.role } });
  })
);

// Students
app.get('/api/students', authMiddleware, asyncHandler(async (req,res) => {
  const list = await Student.find().sort({ createdAt:-1 });
  res.json(list);
}));
app.post('/api/students', authMiddleware,
  body('fullName').notEmpty().trim().escape(), body('classLevel').notEmpty().trim().escape(),
  asyncHandler(async (req,res)=>{
    const errors = validationResult(req); if(!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
    const s = new Student(req.body); await s.save(); res.json({ message:'Student added', student:s });
  })
);
app.put('/api/students/:id', authMiddleware, asyncHandler(async (req,res)=>{
  const s = await Student.findByIdAndUpdate(req.params.id, req.body, { new:true }); if(!s) return res.status(404).json({ error:'Not found' });
  res.json({ message:'Updated', student:s });
}));
app.delete('/api/students/:id', authMiddleware, roleRequired('admin'), asyncHandler(async (req,res)=>{
  await Student.findByIdAndDelete(req.params.id); res.json({ message:'Deleted' });
}));

// Books
app.get('/api/books', authMiddleware, asyncHandler(async (req,res) => {
  const books = await Book.find();
  res.json(books);
}));
app.post('/api/books', authMiddleware, body('title').notEmpty().trim().escape(), asyncHandler(async (req,res)=>{
  const errors = validationResult(req); if(!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  const b = new Book(req.body); await b.save(); res.json({ message:'Book added', book:b });
}));
app.put('/api/books/:id', authMiddleware, asyncHandler(async (req,res)=>{
  const b = await Book.findByIdAndUpdate(req.params.id, req.body, { new:true }); if(!b) return res.status(404).json({ error:'Not found' });
  res.json({ message:'Updated', book:b });
}));
app.delete('/api/books/:id', authMiddleware, roleRequired('admin'), asyncHandler(async (req,res)=>{
  await Book.findByIdAndDelete(req.params.id); res.json({ message:'Deleted' });
}));

// Attendance
app.get('/api/attendance', authMiddleware, asyncHandler(async (req,res) => {
  const attendance = await Attendance.find().populate('studentId').sort({ date:-1 });
  res.json(attendance);
}));
app.post('/api/attendance', authMiddleware,
  body('studentId').notEmpty().trim(),
  body('date').notEmpty(),
  body('status').isIn(['present','absent','late']),
  asyncHandler(async (req,res)=>{
    const errors = validationResult(req); if(!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
    const a = new Attendance(req.body); await a.save(); res.json({ message:'Attendance recorded', attendance:a });
  })
);

// global error handler
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Internal server error' });
});

// optional: create initial admin if none exists (use env vars)
(async function ensureAdmin(){
  try {
    const adminEmail = process.env.ADMIN_EMAIL;
    const adminPassword = process.env.ADMIN_PASSWORD;
    if (adminEmail && adminPassword) {
      const exists = await User.findOne({ email: adminEmail.toLowerCase() });
      if (!exists) {
        const passwordHash = await bcrypt.hash(adminPassword, 10);
        const u = new User({ name: 'Administrator', email: adminEmail.toLowerCase(), passwordHash, role: 'admin' });
        await u.save();
        console.log('Admin user created:', adminEmail);
      }
    }
  } catch(e){ console.error('Admin seed error', e); }
})();

app.listen(PORT, ()=> console.log(`Server running on ${PORT}`));
