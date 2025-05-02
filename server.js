const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const app = express();
const PORT = process.env.PORT || 8000;

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB Bağlantısı
mongoose.connect('mongodb+srv://eyup:D0ufczveKH9z6oeJ@cluster0.rl4cnoc.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0', {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => {
  console.log('MongoDB bağlantısı başarılı');
}).catch(err => {
  console.error('MongoDB bağlantı hatası:', err);
});

// Kullanıcı Modeli
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// Senaryo Modeli
const scenarioSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  username: { type: String, required: true },
  ongoruler: { type: String, required: true },
  scenario: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const Scenario = mongoose.model('Scenario', scenarioSchema);

// JWT Secret
const JWT_SECRET = 'your-secret-key'; // Gerçek bir uygulamada çevresel değişkenlerden alınmalı

// Kimlik Doğrulama Middleware
const auth = (req, res, next) => {
  try {
    const token = req.header('Authorization').replace('Bearer ', '');
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (error) {
    res.status(401).send({ error: 'Lütfen giriş yapın' });
  }
};

// Senaryo kaydetme
app.post('/api/save_scenario', auth, async (req, res) => {
  try {
    const { ongoruler, scenario } = req.body;
    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
    }

    const newScenario = new Scenario({
      userId: req.userId,
      username: user.username,
      ongoruler,
      scenario
    });

    await newScenario.save();

    res.status(201).json({ 
      message: 'Senaryo başarıyla kaydedildi',
      scenario: newScenario
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// Senaryoları listeleme
app.get('/api/scenarios', auth, async (req, res) => {
  try {
    const scenarios = await Scenario.find().sort({ createdAt: -1 });
    res.status(200).json({ scenarios });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// Kayıt Olma
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(400).json({ error: 'Bu kullanıcı adı veya e-posta zaten kullanılıyor' });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const user = new User({
      username,
      email,
      password: hashedPassword
    });

    await user.save();

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1d' });

    res.status(201).json({
      message: 'Kayıt başarılı',
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// Giriş Yapma
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(400).json({ error: 'Geçersiz kullanıcı adı veya şifre' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: 'Geçersiz kullanıcı adı veya şifre' });
    }

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1d' });

    res.status(200).json({
      message: 'Giriş başarılı',
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// Kullanıcı bilgisi kontrol
app.get('/api/user', auth, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('-password');
    if (!user) {
      return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
    }
    res.status(200).json({ user });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

app.listen(PORT, () => {
  console.log(`Server ${PORT} portunda çalışıyor`);
});