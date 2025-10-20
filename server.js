const express = require('express');
const cors = require('cors');
const https = require('https');
const path = require('path');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;

// MySQL配置 - 直接写在代码中
const dbConfig = {
  host: '120.26.16.9',
  user: 'novel_user',
  password: 'Novel@050609',
  database: 'novel_app',
  port: 3306
};

// 创建连接池
const pool = mysql.createPool(dbConfig);

// 初始化数据库表
async function initDatabase() {
  try {
    const connection = await pool.getConnection();
    
    // 创建用户表
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    console.log('✅ 数据库表初始化成功');
    connection.release();
  } catch (error) {
    console.error('❌ 数据库初始化失败:', error.message);
  }
}

// 调用初始化
initDatabase();

// 中间件
app.use(cors());
app.use(express.json());

// 直接写在代码中的密钥
const JWT_SECRET = 'your-very-strong-secret-key-for-jwt-encryption';
const API_KEY = 'a14b5cdff147b1262882db2ca29355bd';
const BASE_URL = 'https://api.xcvts.cn/api/xiaoshuo/axdzs';

// 认证中间件
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: '访问令牌不存在' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: '令牌无效' });
    }
    req.user = user;
    next();
  });
};

// API请求函数
function makeRequest(url) {
  return new Promise((resolve, reject) => {
    https.get(url, (response) => {
      let data = '';
      response.on('data', (chunk) => data += chunk);
      response.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch (error) {
          reject(new Error('解析JSON失败: ' + error.message));
        }
      });
    }).on('error', reject);
  });
}

// 用户注册
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ error: '请填写所有字段' });
    }

    // 检查用户是否已存在
    const [existingUsers] = await pool.execute(
      'SELECT id FROM users WHERE email = ? OR username = ?',
      [email, username]
    );
    
    if (existingUsers.length > 0) {
      return res.status(400).json({ error: '用户名或邮箱已存在' });
    }

    // 加密密码
    const hashedPassword = await bcrypt.hash(password, 10);

    // 创建用户
    const [result] = await pool.execute(
      'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
      [username, email, hashedPassword]
    );

    // 生成JWT令牌
    const token = jwt.sign(
      { userId: result.insertId, username: username }, 
      JWT_SECRET
    );

    res.status(201).json({
      message: '注册成功',
      token,
      user: { id: result.insertId, username, email }
    });

  } catch (error) {
    console.error('注册错误:', error);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// 用户登录
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: '请填写邮箱和密码' });
    }

    // 查找用户
    const [users] = await pool.execute(
      'SELECT * FROM users WHERE email = ?',
      [email]
    );
    
    if (users.length === 0) {
      return res.status(400).json({ error: '用户不存在' });
    }

    const user = users[0];

    // 验证密码
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(400).json({ error: '密码错误' });
    }

    // 生成JWT令牌
    const token = jwt.sign(
      { userId: user.id, username: user.username }, 
      JWT_SECRET
    );

    res.json({
      message: '登录成功',
      token,
      user: { id: user.id, username: user.username, email: user.email }
    });

  } catch (error) {
    console.error('登录错误:', error);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// 获取用户信息
app.get('/api/user', authenticateToken, async (req, res) => {
  try {
    const [users] = await pool.execute(
      'SELECT id, username, email, created_at FROM users WHERE id = ?',
      [req.user.userId]
    );
    
    if (users.length === 0) {
      return res.status(404).json({ error: '用户不存在' });
    }

    res.json(users[0]);
  } catch (error) {
    res.status(500).json({ error: '获取用户信息失败' });
  }
});

// 搜索路由（需要登录）
app.get('/api/search', authenticateToken, async (req, res) => {
  try {
    const query = req.query.q;
    
    if (!query) {
      return res.status(400).json({ error: '缺少查询参数 q' });
    }
    
    const apiUrl = `${BASE_URL}?apiKey=${API_KEY}&q=${encodeURIComponent(query)}`;
    console.log('搜索请求:', apiUrl);
    
    const data = await makeRequest(apiUrl);
    
    res.json(data);
  } catch (error) {
    console.error('搜索错误:', error);
    res.status(500).json({ error: '搜索失败: ' + error.message });
  }
});

// 下载路由（需要登录）
app.get('/api/download', authenticateToken, async (req, res) => {
  try {
    const { q, n } = req.query;
    
    if (!q || !n) {
      return res.status(400).json({ error: '缺少必要的查询参数' });
    }
    
    const downloadUrl = `${BASE_URL}?apiKey=${API_KEY}&q=${encodeURIComponent(q)}&n=${n}`;
    console.log('下载重定向:', downloadUrl);
    
    res.redirect(downloadUrl);
  } catch (error) {
    console.error('下载错误:', error);
    res.status(500).json({ error: '下载失败: ' + error.message });
  }
});

// 健康检查端点
app.get('/api/health', async (req, res) => {
  try {
    // 测试数据库连接
    await pool.execute('SELECT 1');
    res.json({ 
      status: 'ok', 
      database: 'connected',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({ 
      status: 'error', 
      database: 'disconnected',
      error: error.message 
    });
  }
});

// 提供静态文件（HTML页面）
app.use(express.static('.'));

// 根路径返回首页
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// 只在非Vercel环境下启动服务器监听
if (process.env.VERCEL !== '1') {
  app.listen(PORT, () => {
    console.log(`🚀 服务器运行在 http://localhost:${PORT}`);
    console.log(`🗄️  MySQL数据库已连接`);
    console.log(`🔐 用户认证系统已启用`);
    console.log(`🔍 搜索接口: http://localhost:${PORT}/api/search?q=小说名称`);
    console.log(`📥 下载接口: http://localhost:${PORT}/api/download?q=小说名称&n=序号`);
    console.log(`🌐 网页地址: http://localhost:${PORT}`);
  });
}

// 导出app给Vercel使用
module.exports = app;