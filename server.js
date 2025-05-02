// const express = require('express');
// const mongoose = require('mongoose');
// const cors = require('cors');
// const bcrypt = require('bcryptjs');
// const jwt = require('jsonwebtoken');
// const app = express();
// const PORT = process.env.PORT || 8000;

// // Middleware
// app.use(cors());
// app.use(express.json());

// // MongoDB Bağlantısı
// mongoose.connect('mongodb+srv://eyup:D0ufczveKH9z6oeJ@cluster0.rl4cnoc.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0', {
//   useNewUrlParser: true,
//   useUnifiedTopology: true
// }).then(() => {
//   console.log('MongoDB bağlantısı başarılı');
// }).catch(err => {
//   console.error('MongoDB bağlantı hatası:', err);
// });

// // Kullanıcı Modeli
// const userSchema = new mongoose.Schema({
//   username: { type: String, required: true, unique: true },
//   email: { type: String, required: true, unique: true },
//   password: { type: String, required: true },
//   createdAt: { type: Date, default: Date.now }
// });

// const User = mongoose.model('User', userSchema);

// // Senaryo Modeli
// const scenarioSchema = new mongoose.Schema({
//   userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
//   username: { type: String, required: true },
//   ongoruler: { type: String, required: true },
//   scenario: { type: String, required: true },
//   createdAt: { type: Date, default: Date.now }
// });

// const Scenario = mongoose.model('Scenario', scenarioSchema);

// // JWT Secret
// const JWT_SECRET = 'your-secret-key'; // Gerçek bir uygulamada çevresel değişkenlerden alınmalı

// // Kimlik Doğrulama Middleware
// const auth = (req, res, next) => {
//   try {
//     const token = req.header('Authorization').replace('Bearer ', '');
//     const decoded = jwt.verify(token, JWT_SECRET);
//     req.userId = decoded.userId;
//     next();
//   } catch (error) {
//     res.status(401).send({ error: 'Lütfen giriş yapın' });
//   }
// };

// // Senaryo kaydetme
// app.post('/api/save_scenario', auth, async (req, res) => {
//   try {
//     const { ongoruler, scenario } = req.body;
//     const user = await User.findById(req.userId);
//     if (!user) {
//       return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
//     }

//     const newScenario = new Scenario({
//       userId: req.userId,
//       username: user.username,
//       ongoruler,
//       scenario
//     });

//     await newScenario.save();

//     res.status(201).json({ 
//       message: 'Senaryo başarıyla kaydedildi',
//       scenario: newScenario
//     });
//   } catch (error) {
//     console.error(error);
//     res.status(500).json({ error: 'Sunucu hatası' });
//   }
// });

// // Senaryoları listeleme
// app.get('/api/scenarios', auth, async (req, res) => {
//   try {
//     const scenarios = await Scenario.find().sort({ createdAt: -1 });
//     res.status(200).json({ scenarios });
//   } catch (error) {
//     console.error(error);
//     res.status(500).json({ error: 'Sunucu hatası' });
//   }
// });

// // Kayıt Olma
// app.post('/api/register', async (req, res) => {
//   try {
//     const { username, email, password } = req.body;
//     const existingUser = await User.findOne({ $or: [{ email }, { username }] });
//     if (existingUser) {
//       return res.status(400).json({ error: 'Bu kullanıcı adı veya e-posta zaten kullanılıyor' });
//     }

//     const salt = await bcrypt.genSalt(10);
//     const hashedPassword = await bcrypt.hash(password, salt);

//     const user = new User({
//       username,
//       email,
//       password: hashedPassword
//     });

//     await user.save();

//     const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1d' });

//     res.status(201).json({
//       message: 'Kayıt başarılı',
//       token,
//       user: {
//         id: user._id,
//         username: user.username,
//         email: user.email
//       }
//     });
//   } catch (error) {
//     console.error(error);
//     res.status(500).json({ error: 'Sunucu hatası' });
//   }
// });

// // Giriş Yapma
// app.post('/api/login', async (req, res) => {
//   try {
//     const { username, password } = req.body;
//     const user = await User.findOne({ username });
//     if (!user) {
//       return res.status(400).json({ error: 'Geçersiz kullanıcı adı veya şifre' });
//     }

//     const isMatch = await bcrypt.compare(password, user.password);
//     if (!isMatch) {
//       return res.status(400).json({ error: 'Geçersiz kullanıcı adı veya şifre' });
//     }

//     const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1d' });

//     res.status(200).json({
//       message: 'Giriş başarılı',
//       token,
//       user: {
//         id: user._id,
//         username: user.username,
//         email: user.email
//       }
//     });
//   } catch (error) {
//     console.error(error);
//     res.status(500).json({ error: 'Sunucu hatası' });
//   }
// });

// // Kullanıcı bilgisi kontrol
// app.get('/api/user', auth, async (req, res) => {
//   try {
//     const user = await User.findById(req.userId).select('-password');
//     if (!user) {
//       return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
//     }
//     res.status(200).json({ user });
//   } catch (error) {
//     console.error(error);
//     res.status(500).json({ error: 'Sunucu hatası' });
//   }
// });

// app.listen(PORT, () => {
//   console.log(`Server ${PORT} portunda çalışıyor`);
// });
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

// Takım Modeli (Yeni)
const teamSchema = new mongoose.Schema({
  teamId: { type: String, required: true, unique: true },
  teamName: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const Team = mongoose.model('Team', teamSchema);

// Kategori Modeli (Yeni)
const categorySchema = new mongoose.Schema({
  name: { type: String, required: true, unique: true },
  createdAt: { type: Date, default: Date.now }
});

const Category = mongoose.model('Category', categorySchema);

// Kullanıcı Modeli (Güncellenmiş)
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  teamId: { type: String, required: true }, // Takım kimliği
  isAdmin: { type: Boolean, default: false }, // Admin yetkisi
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// Senaryo Modeli (Güncellenmiş)
const scenarioSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  username: { type: String, required: true },
  teamId: { type: String, required: true }, // Takım kimliği
  teamName: { type: String, required: true }, // Takım adı
  ongoruler: { type: String, required: true },
  scenario: { type: String, required: true },
  category: { type: String, default: 'Kategorisiz' }, // Kategori
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

// Admin Yetkisi Kontrolü Middleware
const isAdmin = async (req, res, next) => {
  try {
    const user = await User.findById(req.userId);
    if (!user || !user.isAdmin) {
      return res.status(403).json({ error: 'Bu işlem için admin yetkisi gerekiyor' });
    }
    next();
  } catch (error) {
    res.status(500).json({ error: 'Sunucu hatası' });
  }
};

// Senaryo kaydetme (Güncellenmiş)
app.post('/api/save_scenario', auth, async (req, res) => {
  try {
    const { ongoruler, scenario } = req.body;
    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
    }

    // Kullanıcının takım bilgisini al
    const team = await Team.findOne({ teamId: user.teamId });
    const teamName = team ? team.teamName : 'Bilinmeyen Takım';

    const newScenario = new Scenario({
      userId: req.userId,
      username: user.username,
      teamId: user.teamId,
      teamName: teamName,
      ongoruler,
      scenario,
      category: 'Kategorisiz' // Varsayılan kategori
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

// Senaryoları listeleme (Güncellenmiş - Takım yetkilerine göre)
app.get('/api/scenarios', auth, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
    }

    let scenarios;
    
    // Admin tüm senaryoları görebilir
    if (user.isAdmin) {
      scenarios = await Scenario.find().sort({ createdAt: -1 });
    } else {
      // Normal kullanıcı sadece kendi takımının senaryolarını görebilir
      scenarios = await Scenario.find({ teamId: user.teamId }).sort({ createdAt: -1 });
    }
    
    res.status(200).json({ scenarios });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// Senaryoları kategoriye göre filtreleme (Yeni)
app.get('/api/scenarios/filter', auth, async (req, res) => {
  try {
    const { category } = req.query;
    const user = await User.findById(req.userId);
    
    if (!user) {
      return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
    }

    let query = {};
    
    // Kategori filtreleme
    if (category && category !== 'all') {
      query.category = category;
    }
    
    // Admin olmayan kullanıcılar sadece kendi takımlarının senaryolarını görebilir
    if (!user.isAdmin) {
      query.teamId = user.teamId;
    }
    
    const scenarios = await Scenario.find(query).sort({ createdAt: -1 });
    res.status(200).json({ scenarios });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// Senaryo kategorisini güncelleme (Yeni - Sadece adminler için)
app.put('/api/scenarios/:scenarioId/category', auth, isAdmin, async (req, res) => {
  try {
    const { scenarioId } = req.params;
    const { category } = req.body;
    
    const updatedScenario = await Scenario.findByIdAndUpdate(
      scenarioId,
      { category },
      { new: true }
    );
    
    if (!updatedScenario) {
      return res.status(404).json({ error: 'Senaryo bulunamadı' });
    }
    
    res.status(200).json({ 
      message: 'Kategori başarıyla güncellendi',
      scenario: updatedScenario
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// Tüm kategorileri listeleme
app.get('/api/categories', auth, async (req, res) => {
  try {
    const categories = await Category.find().sort({ name: 1 });
    res.status(200).json({ categories });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// Yeni kategori ekleme (Sadece adminler için)
app.post('/api/categories', auth, isAdmin, async (req, res) => {
  try {
    const { name } = req.body;
    
    const existingCategory = await Category.findOne({ name });
    if (existingCategory) {
      return res.status(400).json({ error: 'Bu kategori zaten mevcut' });
    }
    
    const newCategory = new Category({ name });
    await newCategory.save();
    
    res.status(201).json({
      message: 'Kategori başarıyla eklendi',
      category: newCategory
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// Tüm takımları listeleme (Sadece adminler için)
app.get('/api/teams', auth, isAdmin, async (req, res) => {
  try {
    const teams = await Team.find().sort({ teamName: 1 });
    res.status(200).json({ teams });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// Takımları listeleme (Kayıt sayfası için - kimlik doğrulama gerekmez)
app.get('/api/public/teams', async (req, res) => {
  try {
    // Admin takımını hariç tut
    const teams = await Team.find({ teamId: { $ne: 'admin' } }).sort({ teamName: 1 });
    res.status(200).json({ teams });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// Yeni takım ekleme (Sadece adminler için)
app.post('/api/teams', auth, isAdmin, async (req, res) => {
  try {
    const { teamId, teamName } = req.body;
    
    const existingTeam = await Team.findOne({ $or: [{ teamId }, { teamName }] });
    if (existingTeam) {
      return res.status(400).json({ error: 'Bu takım ID veya ismi zaten kullanılıyor' });
    }
    
    const newTeam = new Team({ teamId, teamName });
    await newTeam.save();
    
    res.status(201).json({
      message: 'Takım başarıyla eklendi',
      team: newTeam
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// Kayıt Olma (Güncellenmiş - takım seçimi ile)
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password, teamId } = req.body;
    
    // Kullanıcı adı veya e-posta kontrolü
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(400).json({ error: 'Bu kullanıcı adı veya e-posta zaten kullanılıyor' });
    }
    
    // Takım kontrolü
    const team = await Team.findOne({ teamId });
    if (!team && teamId !== 'admin') {  // admin özel bir takım ID'si
      return res.status(400).json({ error: 'Geçersiz takım ID' });
    }
    
    // Şifreyi hashle
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    
    // Admin kontrolü - admin takım ID'si verilmişse admin yetkisi ver
    const isAdmin = teamId === 'admin';
    
    const user = new User({
      username,
      email,
      password: hashedPassword,
      teamId: isAdmin ? 'admin' : teamId,
      isAdmin
    });

    await user.save();

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1d' });

    res.status(201).json({
      message: 'Kayıt başarılı',
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        teamId: user.teamId,
        isAdmin: user.isAdmin
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// Giriş Yapma (Güncellenmiş - takım ve admin bilgilerini döndürür)
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
        email: user.email,
        teamId: user.teamId,
        isAdmin: user.isAdmin
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// Kullanıcı bilgisi kontrol (Güncellenmiş - takım ve admin bilgilerini içerir)
app.get('/api/user', auth, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('-password');
    if (!user) {
      return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
    }
    
    // Takım bilgisini ekle
    const team = await Team.findOne({ teamId: user.teamId });
    
    res.status(200).json({ 
      user: {
        ...user.toObject(),
        teamName: team ? team.teamName : 'Bilinmeyen Takım'
      } 
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// Başlangıçta varsayılan takımları ve kategorileri oluştur
const initializeData = async () => {
  try {
    // Admin takımını kontrol et ve yoksa oluştur
    const adminTeam = await Team.findOne({ teamId: 'admin' });
    if (!adminTeam) {
      await new Team({ teamId: 'admin', teamName: 'Yönetim Ekibi' }).save();
      console.log('Admin takımı oluşturuldu');
    }
    
    // Varsayılan bir takım oluştur
    const defaultTeam = await Team.findOne({ teamId: 'default' });
    if (!defaultTeam) {
      await new Team({ teamId: 'default', teamName: 'Genel Ekip' }).save();
      console.log('Varsayılan takım oluşturuldu');
    }
    
    // Varsayılan kategorileri oluştur
    const categories = ['Kategorisiz', 'Ekonomi', 'Teknoloji', 'Sağlık', 'Eğitim'];
    for (const categoryName of categories) {
      const existingCategory = await Category.findOne({ name: categoryName });
      if (!existingCategory) {
        await new Category({ name: categoryName }).save();
        console.log(`"${categoryName}" kategorisi oluşturuldu`);
      }
    }
  } catch (error) {
    console.error('Veri başlatma hatası:', error);
  }
};

// Sunucu başlatıldığında veri başlatma
app.listen(PORT, () => {
  console.log(`Server ${PORT} portunda çalışıyor`);
  initializeData();
});