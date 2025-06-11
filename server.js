// server.js
const express       = require('express');
const session       = require('express-session');
const bodyParser    = require('body-parser');
const bcrypt        = require('bcrypt');
const fs            = require('fs');
const path          = require('path');

const app = express();
const USERS_FILE = path.join(__dirname, 'users.json');

// body parser
app.use(bodyParser.urlencoded({ extended: false }));

// session
app.use(session({
  secret: 'gizli_cumle',     // production’da ENV’den al
  resave: false,
  saveUninitialized: false
}));

// statik dosyalar
app.use(express.static(path.join(__dirname, 'public')));

// helper: JSON’den kullanıcıları oku/yaz
function readUsers(){
  if (!fs.existsSync(USERS_FILE)) return {};
  const raw = fs.readFileSync(USERS_FILE, 'utf8').trim();
  if (!raw) return {};               // dosya boşsa yine {}
  try {
    return JSON.parse(raw);
  } catch (err) {
    console.error('users.json parse error:', err);
    return {};
  }
}

function writeUsers(u){ fs.writeFileSync(USERS_FILE, JSON.stringify(u,null,2)); }

// middleware: auth kontrol
function requireAuth(req, res, next){
  if(req.session && req.session.user) return next();
  res.redirect('/login.html');
}

// Kayıt endpoint
app.post('/register', async (req,res) => {
  const { username, password } = req.body;
  let users = readUsers();
  if(users[username]){
    return res.send('Bu kullanıcı zaten kayıtlı. <a href="/register.html">Geri</a>');
  }
  const hash = await bcrypt.hash(password, 10);
  users[username] = { password: hash };
  writeUsers(users);
  res.redirect('/login.html');
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const users = readUsers();
  if (!users[username] || !await bcrypt.compare(password, users[username].password)) {
    // eski res.send’i kaldır, yerine redirect koy
    return res.redirect('/login.html?error=1');
  }
  req.session.user = username;
  res.redirect('/encrypt.html');
});
// Logout
app.get('/logout', (req,res)=>{
  req.session.destroy();
  res.redirect('/login.html'); 
});

// Şifreleme sayfasını koru
app.get('/encrypt.html', requireAuth, (req,res,next)=>{
  next(); // public içindeki encrypt.html’i göster
});

// Sunucu
const PORT = 3000;
app.listen(PORT, ()=>{
  console.log(`http://localhost:${PORT} üzerinde çalışıyor`);
});
