// index.js
require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
});

// Helper: obtener usuario por username
async function getUserByUsername(username){
  const [rows] = await pool.query('SELECT * FROM usuarios WHERE username = ?', [username]);
  return rows[0];
}

// Rutas públicas
// 1) noticias activas (fecha_expiracion > NOW())
app.get('/noticias', async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT id_noticia, contenido, fecha_publicacion, fecha_expiracion, id_autor FROM noticias WHERE fecha_expiracion > NOW() ORDER BY fecha_publicacion DESC'
    );
    res.json({ data: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'db_error' });
  }
});

// 2) noticias pasadas (tabla noticiasPasadas)
app.get('/noticias/pasadas', async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT id_noticia, contenido, fecha_publicacion, fecha_expiracion FROM noticiasPasadas ORDER BY fecha_publicacion DESC'
    );
    res.json({ data: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'db_error' });
  }
});

// Auth: login (dev-demo)
// Nota: en tu SQL existe un usuario admin creado con contrasenia 'Admin123' (en texto).
// Para demo, el código soporta tanto hashes bcrypt como texto plano.
app.post('/auth/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'missing_credentials' });
  try {
    const user = await getUserByUsername(username);
    if (!user) return res.status(401).json({ error: 'invalid_credentials' });

    let ok = false;
    try {
      ok = await bcrypt.compare(password, user.contrasenia_hash);
    } catch (e) {
      // si falló comparar bcrypt, tal vez la contraseña está en texto plano (como en tu SQL de ejemplo)
      ok = (password === user.contrasenia_hash);
    }
    if (!ok) return res.status(401).json({ error: 'invalid_credentials' });

    const token = jwt.sign(
      { id: user.id_usuario, username: user.username, is_admin: user.is_admin },
      process.env.JWT_SECRET,
      { expiresIn: '8h' }
    );
    res.json({ token, is_admin: user.is_admin });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'db_error' });
  }
});

// Middleware auth
function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'no_token' });
  const token = auth.split(' ')[1];
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    req.user = payload;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'invalid_token' });
  }
}

// Crear noticia (solo admin)
app.post('/noticias', authMiddleware, async (req, res) => {
  if (!req.user.is_admin) return res.status(403).json({ error: 'forbidden' });
  const { contenido, fecha_expiracion } = req.body;
  if (!contenido || !fecha_expiracion) return res.status(400).json({ error: 'missing_fields' });
  try {
    const fecha_publicacion = new Date();
    const [result] = await pool.query(
      'INSERT INTO noticias (contenido, fecha_publicacion, fecha_expiracion, id_autor) VALUES (?, ?, ?, ?)',
      [contenido, fecha_publicacion, fecha_expiracion, req.user.id]
    );
    const insertId = result.insertId;
    const [rows] = await pool.query('SELECT id_noticia, contenido, fecha_publicacion, fecha_expiracion, id_autor FROM noticias WHERE id_noticia = ?', [insertId]);
    res.status(201).json({ data: rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'db_error' });
  }
});

// simple health
app.get('/ping', (req, res) => res.json({ ok: true }));

const port = process.env.PORT || 8080;
app.listen(port, () => console.log('API corriendo en: ', port));
