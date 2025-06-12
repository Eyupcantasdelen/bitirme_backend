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

// Takım Modeli
const teamSchema = new mongoose.Schema({
  teamId: { type: String, required: true, unique: true },
  teamName: { type: String, required: true },
  teamLeaderId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null }, // Takım lideri
  createdAt: { type: Date, default: Date.now }
});

const Team = mongoose.model('Team', teamSchema);

// Kategori Modeli
const categorySchema = new mongoose.Schema({
  name: { type: String, required: true, unique: true },
  createdAt: { type: Date, default: Date.now }
});

const Category = mongoose.model('Category', categorySchema);

// Kullanıcı Modeli (Güncellenmiş - Takım Lideri Rolü Eklendi)
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  teamId: { type: String, required: true },
  isAdmin: { type: Boolean, default: false },
  isTeamLeader: { type: Boolean, default: false }, // Yeni: Takım lideri rolü
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// Senaryo Modeli (Güncellenmiş - Onay Sistemi Eklendi)
const scenarioSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  username: { type: String, required: true },
  teamId: { type: String, required: true },
  teamName: { type: String, required: true },
  ongoruler: { type: String, required: true },
  scenario: { type: String, required: true },
  category: { type: String, default: 'Kategorisiz' },
  
  // Yeni: Onay sistemi için alanlar
  approvalStatus: { 
    type: String, 
    enum: ['approved', 'pending', 'rejected'], 
    default: 'approved' // İlk oluşturulan senaryolar otomatik onaylı
  },
  approvedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  approvalDate: { type: Date, default: null },
  rejectionReason: { type: String, default: null },
  
  // Düzenleme geçmişi
  editHistory: [{
    editedAt: { type: Date, default: Date.now },
    previousOngoruler: { type: String },
    previousScenario: { type: String },
    editReason: { type: String }
  }],
  
  isEdited: { type: Boolean, default: false },
  lastEditedAt: { type: Date, default: null },
  
  createdAt: { type: Date, default: Date.now }
});

const Scenario = mongoose.model('Scenario', scenarioSchema);

// JWT Secret
const JWT_SECRET = 'your-secret-key';

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

// Takım Lideri Yetkisi Kontrolü Middleware
const isTeamLeader = async (req, res, next) => {
  try {
    const user = await User.findById(req.userId);
    if (!user || (!user.isTeamLeader && !user.isAdmin)) {
      return res.status(403).json({ error: 'Bu işlem için takım lideri veya admin yetkisi gerekiyor' });
    }
    req.user = user;
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

    const team = await Team.findOne({ teamId: user.teamId });
    const teamName = team ? team.teamName : 'Bilinmeyen Takım';

    const newScenario = new Scenario({
      userId: req.userId,
      username: user.username,
      teamId: user.teamId,
      teamName: teamName,
      ongoruler,
      scenario,
      category: 'Kategorisiz',
      approvalStatus: 'approved' // Yeni senaryolar otomatik onaylı
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

// Senaryo düzenleme (Yeni)
app.put('/api/scenarios/:scenarioId/edit', auth, async (req, res) => {
  try {
    const { scenarioId } = req.params;
    const { ongoruler, scenario, editReason } = req.body;
    const user = await User.findById(req.userId);
    
    if (!user) {
      return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
    }

    const existingScenario = await Scenario.findById(scenarioId);
    if (!existingScenario) {
      return res.status(404).json({ error: 'Senaryo bulunamadı' });
    }

    // Sadece kendi senaryosunu düzenleyebilir (admin hariç)
    if (!user.isAdmin && existingScenario.userId.toString() !== req.userId) {
      return res.status(403).json({ error: 'Bu senaryoyu düzenleme yetkiniz yok' });
    }

    // Düzenleme geçmişine ekle
    existingScenario.editHistory.push({
      editedAt: new Date(),
      previousOngoruler: existingScenario.ongoruler,
      previousScenario: existingScenario.scenario,
      editReason: editReason || 'Düzenleme nedeni belirtilmedi'
    });

    // Senaryoyu güncelle
    existingScenario.ongoruler = ongoruler;
    existingScenario.scenario = scenario;
    existingScenario.isEdited = true;
    existingScenario.lastEditedAt = new Date();
    existingScenario.approvalStatus = 'pending'; // Düzenleme sonrası onay beklemede
    existingScenario.approvedBy = null;
    existingScenario.approvalDate = null;
    existingScenario.rejectionReason = null;

    await existingScenario.save();

    res.status(200).json({ 
      message: 'Senaryo başarıyla düzenlendi ve onay için gönderildi',
      scenario: existingScenario
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// Senaryoları onaylama/reddetme (Takım lideri için)
app.put('/api/scenarios/:scenarioId/approve', auth, isTeamLeader, async (req, res) => {
  try {
    const { scenarioId } = req.params;
    const { action, rejectionReason } = req.body; // action: 'approve' veya 'reject'
    
    const scenario = await Scenario.findById(scenarioId);
    if (!scenario) {
      return res.status(404).json({ error: 'Senaryo bulunamadı' });
    }

    // Takım lideri sadece kendi takımının senaryolarını onaylayabilir (admin hariç)
    if (!req.user.isAdmin && scenario.teamId !== req.user.teamId) {
      return res.status(403).json({ error: 'Bu senaryoyu onaylama yetkiniz yok' });
    }

    if (action === 'approve') {
      scenario.approvalStatus = 'approved';
      scenario.approvedBy = req.userId;
      scenario.approvalDate = new Date();
      scenario.rejectionReason = null;
    } else if (action === 'reject') {
      scenario.approvalStatus = 'rejected';
      scenario.rejectionReason = rejectionReason || 'Red nedeni belirtilmedi';
      scenario.approvedBy = req.userId;
      scenario.approvalDate = new Date();
    }

    await scenario.save();

    res.status(200).json({ 
      message: action === 'approve' ? 'Senaryo onaylandı' : 'Senaryo reddedildi',
      scenario 
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// Onay bekleyen senaryoları listeleme (Takım lideri için)
app.get('/api/scenarios/pending-approval', auth, isTeamLeader, async (req, res) => {
  try {
    let query = { approvalStatus: 'pending' };
    
    // Admin olmayan takım liderleri sadece kendi takımlarını görebilir
    if (!req.user.isAdmin) {
      query.teamId = req.user.teamId;
    }
    
    const scenarios = await Scenario.find(query)
      .populate('userId', 'username email')
      .sort({ lastEditedAt: -1 });
    
    res.status(200).json({ scenarios });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// Senaryoları listeleme (Güncellenmiş - onay durumu dahil)
app.get('/api/scenarios', auth, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
    }

    let scenarios;
    
    if (user.isAdmin) {
      scenarios = await Scenario.find().sort({ createdAt: -1 });
    } else {
      scenarios = await Scenario.find({ teamId: user.teamId }).sort({ createdAt: -1 });
    }
    
    res.status(200).json({ scenarios });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// Takım lideri atama (Admin için)
app.put('/api/admin/teams/:teamId/assign-leader', auth, isAdmin, async (req, res) => {
  try {
    const { teamId } = req.params;
    const { userId } = req.body;
    
    // Kullanıcıyı kontrol et
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
    }
    
    // Kullanıcının takımını kontrol et
    if (user.teamId !== teamId) {
      return res.status(400).json({ error: 'Kullanıcı bu takımda değil' });
    }
    
    // Eski takım liderinin yetkisini kaldır
    await User.updateMany(
      { teamId: teamId, isTeamLeader: true },
      { isTeamLeader: false }
    );
    
    // Yeni takım liderini ata
    user.isTeamLeader = true;
    await user.save();
    
    // Takım tablosunu güncelle
    await Team.findOneAndUpdate(
      { teamId: teamId },
      { teamLeaderId: userId }
    );
    
    res.status(200).json({ 
      message: 'Takım lideri başarıyla atandı',
      teamLeader: user
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// Takım liderini kaldırma (Admin için)
app.delete('/api/admin/teams/:teamId/remove-leader', auth, isAdmin, async (req, res) => {
  try {
    const { teamId } = req.params;
    
    // Takım liderinin yetkisini kaldır
    await User.updateMany(
      { teamId: teamId, isTeamLeader: true },
      { isTeamLeader: false }
    );
    
    // Takım tablosunu güncelle
    await Team.findOneAndUpdate(
      { teamId: teamId },
      { teamLeaderId: null }
    );
    
    res.status(200).json({ message: 'Takım lideri başarıyla kaldırıldı' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// Takımları takım lideri bilgisi ile listeleme (Admin için)
app.get('/api/admin/teams-with-leaders', auth, isAdmin, async (req, res) => {
  try {
    const teams = await Team.find()
      .populate('teamLeaderId', 'username email')
      .sort({ teamName: 1 });
    
    res.status(200).json({ teams });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// Senaryoları kategoriye göre filtreleme (Güncellenmiş)
app.get('/api/scenarios/filter', auth, async (req, res) => {
  try {
    const { category } = req.query;
    const user = await User.findById(req.userId);
    
    if (!user) {
      return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
    }

    let query = {};
    
    if (category && category !== 'all') {
      query.category = category;
    }
    
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

// Kayıt Olma (Güncellenmiş)
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password, teamId } = req.body;
    
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(400).json({ error: 'Bu kullanıcı adı veya e-posta zaten kullanılıyor' });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    
    const user = new User({
      username,
      email,
      password: hashedPassword,
      teamId: 'default',
      isAdmin: false,
      isTeamLeader: false
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
        isAdmin: user.isAdmin,
        isTeamLeader: user.isTeamLeader
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// Giriş Yapma (Güncellenmiş)
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
        isAdmin: user.isAdmin,
        isTeamLeader: user.isTeamLeader
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// Kullanıcı bilgisi kontrol (Güncellenmiş)
app.get('/api/user', auth, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('-password');
    if (!user) {
      return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
    }
    
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

// Tüm kullanıcıları listeleme (Sadece adminler için)
app.get('/api/admin/users', auth, isAdmin, async (req, res) => {
  try {
    const users = await User.find().sort({ createdAt: -1 });
    
    const usersWithTeams = await Promise.all(users.map(async (user) => {
      const team = await Team.findOne({ teamId: user.teamId });
      return {
        ...user.toObject(),
        teamName: team ? team.teamName : 'Bilinmeyen Takım'
      };
    }));
    
    res.status(200).json({ users: usersWithTeams });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// Kullanıcı takımını güncelleme (Sadece adminler için)
app.put('/api/admin/users/:userId/team', auth, isAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    const { teamId } = req.body;
    
    const team = await Team.findOne({ teamId });
    if (!team) {
      return res.status(400).json({ error: 'Geçersiz takım ID' });
    }
    
    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { teamId, isTeamLeader: false }, // Takım değiştiğinde takım lideri yetkisini kaldır
      { new: true }
    );
    
    if (!updatedUser) {
      return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
    }
    
    res.status(200).json({ 
      message: 'Kullanıcı takımı başarıyla güncellendi',
      user: updatedUser
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// Başlangıçta varsayılan takımları ve kategorileri oluştur
const initializeData = async () => {
  try {
    const adminTeam = await Team.findOne({ teamId: 'admin' });
    if (!adminTeam) {
      await new Team({ teamId: 'admin', teamName: 'Yönetim Ekibi' }).save();
      console.log('Admin takımı oluşturuldu');
    }
    
    const defaultTeam = await Team.findOne({ teamId: 'default' });
    if (!defaultTeam) {
      await new Team({ teamId: 'default', teamName: 'Genel Ekip' }).save();
      console.log('Varsayılan takım oluşturuldu');
    }
    
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

app.listen(PORT, () => {
  console.log(`Server ${PORT} portunda çalışıyor`);
  initializeData();
});