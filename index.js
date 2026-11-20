require('dotenv').config()
const express = require('express')
const cors = require('cors')
const bcrypt = require('bcryptjs')
const { Pool } = require('pg')
const jwt = require('jsonwebtoken')

const app = express()
app.use(express.json())
app.use(cors())

const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
    options: `-c search_path=${process.env.DB_SCHEMA || 'finpay'}`
})

pool.on('connect', (client) => {
    client.query(`SET search_path TO ${process.env.DB_SCHEMA || 'finpay'}`)
})

const JWT_SECRET = process.env.JWT_SECRET || process.env.DB_SECRET
if (!JWT_SECRET) {
    throw new Error('JWT_SECRET is required')
}

const PORT = 3000
const DEMO_OTP = process.env.DEMO_OTP || '123456'

// =============================================================================
// MIDDLEWARE
// =============================================================================

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization']
  const token = authHeader && authHeader.split(' ')[1]

  if (!token) {
    return res.status(401).json({ success: false, error: 'Доступ запрещен: нет токена' })
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ success: false, error: 'Неверный или просроченный токен' })
    }
    req.user = user
    next()
  })
}

// =============================================================================
// 1. HEALTH CHECK
// =============================================================================

app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1')
    res.json({ success: true, message: 'API is running', timestamp: new Date().toISOString() })
  } catch (error) {
    res.status(500).json({ success: false, error: 'Database connection failed' })
  }
})

// =============================================================================
// 2. AUTH ROUTES
// =============================================================================

const authRouter = express.Router()

// Регистрация
authRouter.post('/register', async (req, res) => {
  try {
    const { phone, fullName, password } = req.body || {}
    if (!phone || !password) {
      return res.status(400).json({ success: false, error: 'Телефон и пароль обязательны' })
    }

    const hashedPassword = await bcrypt.hash(password, 10)
    const client = await pool.connect()
    try {
      await client.query('BEGIN')

      const userRes = await client.query(
        `INSERT INTO users (phone, full_name, password_hash) 
         VALUES ($1, $2, $3) 
         RETURNING id, phone, full_name, status, created_at`,
        [phone, fullName || 'Пользователь', hashedPassword]
      )
      const userId = userRes.rows[0].id

      await client.query(
        `INSERT INTO user_profiles (user_id, preferred_language, preferred_currency) 
         VALUES ($1, 'ru', 'RUB')
         ON CONFLICT (user_id) DO NOTHING`,
        [userId]
      )

      await client.query('COMMIT')

      const token = jwt.sign({ id: userId, phone }, JWT_SECRET, { expiresIn: '7d' })
      res.status(201).json({ success: true, data: { user: userRes.rows[0], token } })
    } catch (e) {
      await client.query('ROLLBACK')
      console.error('DB error:', e.code, e.constraint, e.detail, e.message)
      if (e.code === '23505') {
        return res.status(409).json({ success: false, error: 'Пользователь с таким телефоном уже существует' })
      }
      throw e
    } finally {
      client.release()
    }
  } catch (error) {
    res.status(500).json({ success: false, error: error.message })
  }
})

// Вход
authRouter.post('/login', async (req, res) => {
  try {
    const { phone, password } = req.body || {}
    const result = await pool.query(
      'SELECT id, phone, full_name, password_hash, status, created_at, updated_at FROM users WHERE phone = $1',
      [phone]
    )

    if (result.rows.length === 0) {
      return res.status(401).json({ success: false, error: 'Неверный телефон или пароль' })
    }

    const user = result.rows[0]
    if (user.status !== 'active') {
      return res.status(403).json({ success: false, error: 'Аккаунт заблокирован' })
    }

    const validPassword = await bcrypt.compare(password, user.password_hash)
    if (!validPassword) {
      return res.status(401).json({ success: false, error: 'Неверный телефон или пароль' })
    }

    const token = jwt.sign({ id: user.id, phone: user.phone }, JWT_SECRET, { expiresIn: '7d' })
    delete user.password_hash

    res.json({ success: true, data: { user, token } })
  } catch (error) {
    res.status(500).json({ success: false, error: error.message })
  }
})

// Смена пароля
authRouter.post('/change-password', authenticateToken, async (req, res) => {
  try {
    const { recentPassword, newPassword, confirmPassword } = req.body || {}

    if (!recentPassword || !newPassword || !confirmPassword) {
      return res.status(400).json({ success: false, error: 'Все поля обязательны для заполнения' })
    }

    if (newPassword !== confirmPassword) {
      return res.status(400).json({ success: false, error: 'Новый пароль и подтверждение не совпадают' })
    }

    if (newPassword.length < 6) {
      return res.status(400).json({ success: false, error: 'Пароль должен быть не менее 6 символов' })
    }

    const result = await pool.query(
      'SELECT id, password_hash FROM users WHERE id = $1',
      [req.user.id]
    )

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Пользователь не найден' })
    }

    const user = result.rows[0]
    const validPassword = await bcrypt.compare(recentPassword, user.password_hash)
    if (!validPassword) {
      return res.status(401).json({ success: false, error: 'Неверный текущий пароль' })
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10)
    await pool.query(
      'UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2',
      [hashedPassword, req.user.id]
    )

    res.json({ success: true, message: 'Пароль успешно изменен' })
  } catch (error) {
    res.status(500).json({ success: false, error: error.message })
  }
})

// Обновление токена
authRouter.post('/refresh-token', authenticateToken, async (req, res) => {
  try {
    const token = jwt.sign({ id: req.user.id, phone: req.user.phone }, JWT_SECRET, { expiresIn: '7d' })
    res.json({ success: true, data: { token } })
  } catch (error) {
    res.status(500).json({ success: false, error: error.message })
  }
})

// Восстановление пароля (запрос OTP на телефон)
authRouter.post('/forgot-password', async (req, res) => {
  try {
    const { phone } = req.body || {}
    if (!phone) return res.status(400).json({ success: false, error: 'Телефон обязателен' })

    const result = await pool.query('SELECT id FROM users WHERE phone = $1', [phone])
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Пользователь не найден' })
    }

    res.json({ success: true, message: 'OTP отправлен на телефон', data: { otp: DEMO_OTP } })
  } catch (error) {
    res.status(500).json({ success: false, error: error.message })
  }
})

// Проверка OTP
authRouter.post('/verify-otp', async (req, res) => {
  try {
    const { otp_code, phone } = req.body || {}
    if (!otp_code || !phone) {
      return res.status(400).json({ success: false, error: 'OTP и телефон обязательны' })
    }
    if (otp_code !== DEMO_OTP) {
      return res.status(400).json({ success: false, error: 'Неверный OTP' })
    }
    res.json({ success: true, message: 'OTP подтверждён' })
  } catch (error) {
    res.status(500).json({ success: false, error: error.message })
  }
})

// =============================================================================
// 3. USERS ROUTES
// =============================================================================

const userRouter = express.Router()

// Получить профиль
userRouter.get('/me', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT u.id, u.phone, u.full_name, u.status, u.created_at, u.updated_at,
              up.email, up.city, up.country, up.avatar_url, up.is_verified, up.verification_level
       FROM users u 
       LEFT JOIN user_profiles up ON u.id = up.user_id 
       WHERE u.id = $1`,
      [req.user.id]
    )
    res.json({ success: true, data: result.rows[0] })
  } catch (error) {
    res.status(500).json({ success: false, error: error.message })
  }
})

// Обновить профиль
userRouter.put('/me', authenticateToken, async (req, res) => {
  try {
    const { email, city, country, avatar_url } = req.body || {}
    const result = await pool.query(
      `UPDATE user_profiles 
       SET email = COALESCE($1, email), 
           city = COALESCE($2, city), 
           country = COALESCE($3, country), 
           avatar_url = COALESCE($4, avatar_url), 
           updated_at = NOW()
       WHERE user_id = $5 
       RETURNING *`,
      [email, city, country, avatar_url, req.user.id]
    )
    res.json({ success: true, data: result.rows[0] })
  } catch (error) {
    res.status(500).json({ success: false, error: error.message })
  }
})

// Включить/выключить биометрию
userRouter.patch('/me/biometric', authenticateToken, async (req, res) => {
  try {
    const { biometric_enabled } = req.body || {}
    if (typeof biometric_enabled !== 'boolean') {
      return res.status(400).json({ success: false, error: 'biometric_enabled должен быть boolean' })
    }
    await pool.query(
      `UPDATE user_profiles SET biometric_enabled = $1, updated_at = NOW() WHERE user_id = $2`,
      [biometric_enabled, req.user.id]
    )
    res.json({ success: true, data: { biometric_enabled } })
  } catch (error) {
    res.status(500).json({ success: false, error: error.message })
  }
})

// Смена языка
userRouter.patch('/me/language', authenticateToken, async (req, res) => {
  try {
    const { language } = req.body || {}
    const allowed = ['ru', 'en', 'es']
    if (!language || !allowed.includes(language)) {
      return res.status(400).json({ success: false, error: `Допустимые языки: ${allowed.join(', ')}` })
    }
    await pool.query(
      `UPDATE user_profiles SET preferred_language = $1, updated_at = NOW() WHERE user_id = $2`,
      [language, req.user.id]
    )
    res.json({ success: true, data: { language } })
  } catch (error) {
    res.status(500).json({ success: false, error: error.message })
  }
})

// Количество непрочитанных уведомлений
userRouter.get('/me/notifications-count', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT COUNT(*)::int as unread_count FROM notifications WHERE user_id = $1 AND is_read = FALSE`,
      [req.user.id]
    )
    res.json({ success: true, data: result.rows[0] })
  } catch (error) {
    res.status(500).json({ success: false, error: error.message })
  }
})

// =============================================================================
// 4. CARDS ROUTES
// =============================================================================

const cardRouter = express.Router()

// Список карт
cardRouter.get('/', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, card_type, RIGHT(card_number, 4) as last_4_digits, 
              balance, currency, status, expires_at, created_at
       FROM cards 
       WHERE user_id = $1 
       ORDER BY created_at DESC`,
      [req.user.id]
    )
    res.json({ success: true, data: result.rows })
  } catch (error) {
    res.status(500).json({ success: false, error: error.message })
  }
})

// Детали карты
cardRouter.get('/:id', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT c.id, c.card_type, c.card_number, c.balance, c.currency, c.status, 
              c.expires_at, c.created_at,
              u.full_name as holder_name,
              TO_CHAR(c.created_at, 'MM/YY') as valid_from,
              TO_CHAR(c.expires_at, 'MM/YY') as expires_at_formatted,
              LEFT(c.card_number, 4) || ' **** **** ' || RIGHT(c.card_number, 4) as masked_number,
              RIGHT(c.card_number, 4) as last_4_digits
       FROM cards c 
       JOIN users u ON c.user_id = u.id
       WHERE c.id = $1 AND c.user_id = $2`,
      [req.params.id, req.user.id]
    )
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Карта не найдена' })
    }
    res.json({ success: true, data: result.rows[0] })
  } catch (error) {
    res.status(500).json({ success: false, error: error.message })
  }
})

// Изменить статус карты
cardRouter.patch('/:id/status', authenticateToken, async (req, res) => {
  try {
    const { status } = req.body || {}
    const validStatuses = ['active', 'blocked']
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ 
        success: false, 
        error: `Неверный статус. Допустимые значения: ${validStatuses.join(', ')}` 
      })
    }

    const result = await pool.query(
      `UPDATE cards 
       SET status = $1, updated_at = NOW() 
       WHERE id = $2 AND user_id = $3 
       RETURNING id, card_type, status, balance, currency`,
      [status, req.params.id, req.user.id]
    )
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Карта не найдена' })
    }
    res.json({ success: true, data: result.rows[0] })
  } catch (error) {
    res.status(500).json({ success: false, error: error.message })
  }
})

// Удалить карту (только заблокированную)
cardRouter.delete('/:id', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `DELETE FROM cards 
       WHERE id = $1 AND user_id = $2 AND status = 'blocked' 
       RETURNING id`,
      [req.params.id, req.user.id]
    )
    if (result.rows.length === 0) {
      return res.status(400).json({ 
        success: false, 
        error: 'Можно удалить только заблокированную карту' 
      })
    }
    res.json({ success: true, message: 'Карта удалена' })
  } catch (error) {
    res.status(500).json({ success: false, error: error.message })
  }
})

// Добавить карту
cardRouter.post('/', authenticateToken, async (req, res) => {
  try {
    const { card_number, card_type, expires_at } = req.body || {}
    if (!card_number || !card_type || !expires_at) {
      return res.status(400).json({ success: false, error: 'Все поля обязательны' })
    }
    if (!/^\d{4}-\d{2}-\d{2}$/.test(expires_at)) {
      return res.status(400).json({ success: false, error: 'expires_at должен быть в формате YYYY-MM-DD' })
    }
    const result = await pool.query(
      `INSERT INTO cards (user_id, card_number, card_type, balance, currency, status, expires_at)
       VALUES ($1, $2, $3, 0, 'RUB', 'active', $4)
       RETURNING id, card_type, RIGHT(card_number, 4) as last_4_digits, balance, currency, status, expires_at`,
      [req.user.id, card_number, card_type, expires_at]
    )
    res.status(201).json({ success: true, data: result.rows[0] })
  } catch (error) {
    if (error.code === '23505') {
      return res.status(409).json({ success: false, error: 'Карта с таким номером уже существует' })
    }
    res.status(500).json({ success: false, error: error.message })
  }
})

// Выписка по карте
cardRouter.get('/:id/statements', authenticateToken, async (req, res) => {
  try {
    const { from, to, limit = '50' } = req.query

    // Проверка владельца карты
    const owner = await pool.query(
      'SELECT 1 FROM cards WHERE id = $1 AND user_id = $2',
      [req.params.id, req.user.id]
    )
    if (owner.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Карта не найдена' })
    }

    let query = `
      SELECT t.id, t.amount, t.currency, t.status, t.description, t.created_at,
             t.counterparty_name, c.name as category_name
      FROM transactions t
      LEFT JOIN categories c ON t.category_id = c.id
      WHERE t.account_id = $1
    `
    const params = [req.params.id]
    if (from) { params.push(from); query += ` AND t.created_at >= $${params.length}` }
    if (to) { params.push(to); query += ` AND t.created_at <= $${params.length}` }
    query += ` ORDER BY t.created_at DESC LIMIT $${params.length + 1}`
    params.push(parseInt(limit))

    const result = await pool.query(query, params)
    res.json({ success: true, data: result.rows })
  } catch (error) {
    res.status(500).json({ success: false, error: error.message })
  }
})

// =============================================================================
// 5. TRANSACTIONS ROUTES
// =============================================================================

const transactionRouter = express.Router()

// История операций
transactionRouter.get('/', authenticateToken, async (req, res) => {
  try {
    const { limit = '20', offset = '0', type } = req.query
    let query = `
      SELECT t.id, t.amount, t.currency, t.status, t.description, t.created_at,
             t.counterparty_name, 
             c.name as category_name, c.icon as category_icon, c.type as category_type,
             card.card_type || ' ' || RIGHT(card.card_number, 4) as card_masked
      FROM transactions t
      JOIN cards card ON t.account_id = card.id
      LEFT JOIN categories c ON t.category_id = c.id
      WHERE card.user_id = $1
    `
    const params = [req.user.id]

    if (type === 'income' || type === 'expense') {
      query += ` AND c.type = $${params.length + 1}`
      params.push(type)
    }

    query += ` ORDER BY t.created_at DESC LIMIT $${params.length + 1} OFFSET $${params.length + 2}`
    params.push(parseInt(limit), parseInt(offset))

    const result = await pool.query(query, params)
    res.json({ success: true, data: result.rows })
  } catch (error) {
    res.status(500).json({ success: false, error: error.message })
  }
})

// Детали транзакции
transactionRouter.get('/:id', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT t.id, t.account_id, t.counterparty_account_id, t.counterparty_name,
              t.category_id, t.amount, t.currency, t.status, t.description, t.created_at,
              c.name AS category_name, c.icon AS category_icon, c.type AS category_type,
              card.card_type || ' ' || RIGHT(card.card_number, 4) AS card_masked,
              cp.card_type || ' ' || RIGHT(cp.card_number, 4) AS counterparty_card_masked
       FROM transactions t
       JOIN cards card ON t.account_id = card.id
       LEFT JOIN cards cp ON t.counterparty_account_id = cp.id
       LEFT JOIN categories c ON t.category_id = c.id
       WHERE t.id = $1 AND card.user_id = $2`,
      [req.params.id, req.user.id]
    )
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Транзакция не найдена' })
    }
    res.json({ success: true, data: result.rows[0] })
  } catch (error) {
    res.status(500).json({ success: false, error: error.message })
  }
})

// Перевод средств между картами/счетами
transactionRouter.post('/transfer', authenticateToken, async (req, res) => {
  try {
    const { from_card_id, to_account, amount, recipient_name, description, save_beneficiary } = req.body || {}

    if (!from_card_id || !to_account || !amount) {
      return res.status(400).json({ success: false, error: 'from_card_id, to_account и amount обязательны' })
    }
    const numAmount = Number(amount)
    if (!Number.isFinite(numAmount) || numAmount <= 0) {
      return res.status(400).json({ success: false, error: 'Сумма должна быть больше 0' })
    }

    const client = await pool.connect()
    try {
      await client.query('BEGIN')

      const fromRes = await client.query(
        'SELECT id, user_id, balance, currency, status FROM cards WHERE id = $1',
        [from_card_id]
      )
      if (fromRes.rows.length === 0) throw new Error('Карта-источник не найдена')
      const fromCard = fromRes.rows[0]
      if (fromCard.user_id !== req.user.id) throw new Error('Доступ запрещен')
      if (fromCard.status !== 'active') throw new Error('Карта-источник не активна')
      if (Number(fromCard.balance) < numAmount) throw new Error('Недостаточно средств')

      const toRes = await client.query(
        'SELECT id, user_id, balance, currency, status FROM cards WHERE card_number = $1',
        [to_account]
      )
      const toCard = toRes.rows[0] || null

      const desc = (description && description.trim()) ||
                   (recipient_name ? `Перевод ${recipient_name}` : 'Перевод')

      const outTx = await client.query(
        `INSERT INTO transactions
           (account_id, counterparty_account_id, counterparty_name, amount, currency, status, description)
         VALUES ($1, $2, $3, $4, $5, 'completed', $6)
         RETURNING id`,
        [fromCard.id, toCard ? toCard.id : null, recipient_name || null, -numAmount, fromCard.currency, desc]
      )
      const outTxId = outTx.rows[0].id

      await client.query('UPDATE cards SET balance = balance - $1 WHERE id = $2', [numAmount, fromCard.id])

      let inTxId = null
      if (toCard) {
        if (toCard.status !== 'active') throw new Error('Карта получателя не активна')
        inTxId = (await client.query(
          `INSERT INTO transactions
             (account_id, counterparty_account_id, counterparty_name, amount, currency, status, description)
           VALUES ($1, $2, $3, $4, $5, 'completed', $6)
           RETURNING id`,
          [toCard.id, fromCard.id, null, numAmount, toCard.currency, desc]
        )).rows[0].id
        await client.query('UPDATE cards SET balance = balance + $1 WHERE id = $2', [numAmount, toCard.id])
      }

      if (save_beneficiary && recipient_name) {
        await client.query(
          `INSERT INTO transfer_recipients
             (user_id, recipient_name, recipient_account, recipient_bank, last_transfer_at)
           VALUES ($1, $2, $3, $4, NOW())
           ON CONFLICT (user_id, recipient_account) DO UPDATE
             SET recipient_name = EXCLUDED.recipient_name,
                 recipient_bank = EXCLUDED.recipient_bank,
                 last_transfer_at = NOW()`,
          [req.user.id, recipient_name, to_account, null]
        )
      }

      await client.query('COMMIT')
      res.json({
        success: true,
        message: 'Перевод выполнен',
        data: { transaction_id: outTxId, incoming_transaction_id: inTxId },
      })
    } catch (e) {
      await client.query('ROLLBACK')
      throw e
    } finally {
      client.release()
    }
  } catch (error) {
    res.status(500).json({ success: false, error: error.message })
  }
})

// =============================================================================
// 5.1. BENEFICIARIES ROUTES (работает с transfer_recipients)
// =============================================================================

const beneficiaryRouter = express.Router()

// Список получателей
beneficiaryRouter.get('/', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, user_id, recipient_name, recipient_account, recipient_bank,
              is_favorite, last_transfer_at, created_at
       FROM transfer_recipients
       WHERE user_id = $1
       ORDER BY is_favorite DESC, last_transfer_at DESC NULLS LAST, recipient_name`,
      [req.user.id]
    )
    res.json({ success: true, data: result.rows })
  } catch (error) {
    res.status(500).json({ success: false, error: error.message })
  }
})

// Добавить получателя
beneficiaryRouter.post('/', authenticateToken, async (req, res) => {
  try {
    const { recipient_name, recipient_account, recipient_bank } = req.body || {}
    if (!recipient_name || !recipient_account) {
      return res.status(400).json({ success: false, error: 'recipient_name и recipient_account обязательны' })
    }

    const result = await pool.query(
      `INSERT INTO transfer_recipients
         (user_id, recipient_name, recipient_account, recipient_bank)
       VALUES ($1, $2, $3, $4)
       RETURNING id, user_id, recipient_name, recipient_account, recipient_bank,
                 is_favorite, last_transfer_at, created_at`,
      [req.user.id, recipient_name, recipient_account, recipient_bank || null]
    )
    res.status(201).json({ success: true, data: result.rows[0] })
  } catch (error) {
    if (error.code === '23505') {
      return res.status(409).json({ success: false, error: 'Получатель с таким счётом уже существует' })
    }
    res.status(500).json({ success: false, error: error.message })
  }
})

// Удалить получателя
beneficiaryRouter.delete('/:id', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `DELETE FROM transfer_recipients WHERE id = $1 AND user_id = $2 RETURNING id`,
      [req.params.id, req.user.id]
    )
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Получатель не найден' })
    }
    res.json({ success: true, message: 'Получатель удалён' })
  } catch (error) {
    res.status(500).json({ success: false, error: error.message })
  }
})

// Расчёт комиссии перевода
beneficiaryRouter.get('/fee', authenticateToken, async (req, res) => {
  try {
    const amount = parseFloat(req.query.amount || '0')
    const fee = amount > 0 ? amount * 0.01 : 0
    res.json({ success: true, data: { amount, fee, fee_percent: 1 } })
  } catch (error) {
    res.status(500).json({ success: false, error: error.message })
  }
})

// =============================================================================
// 6. BILLS ROUTES
// =============================================================================

const billRouter = express.Router()

// Профили плательщика
billRouter.get('/profiles', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT bp.id, bp.profile_name, bp.account_code, bp.recipient_name, 
              bp.recipient_address, bp.recipient_phone, bp.is_favorite,
              pr.name as provider_name, pr.category, pr.logo_url
       FROM bill_profiles bp
       JOIN bill_providers pr ON bp.provider_id = pr.id
       WHERE bp.user_id = $1 
       ORDER BY bp.is_favorite DESC, bp.profile_name`,
      [req.user.id]
    )
    res.json({ success: true, data: result.rows })
  } catch (error) {
    res.status(500).json({ success: false, error: error.message })
  }
})

// Поиск счёта по коду (ДО /:id)
billRouter.get('/find', authenticateToken, async (req, res) => {
  try {
    const { code } = req.query
    if (!code) {
      return res.status(400).json({ success: false, error: 'Код счёта обязателен' })
    }
    const result = await pool.query(
      `SELECT b.id, b.bill_number, b.total_amount, b.currency, b.status,
              b.period_from, b.period_to, b.service_fee, b.tax, b.penalty,
              b.due_date, b.issue_date,
              bp.recipient_name, bp.recipient_address, bp.recipient_phone
       FROM bills b
       LEFT JOIN bill_profiles bp ON b.bill_profile_id = bp.id
       WHERE b.bill_number = $1 OR bp.account_code = $1
       LIMIT 1`,
      [code]
    )
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Счёт не найден' })
    }
    res.json({ success: true, data: result.rows[0] })
  } catch (error) {
    res.status(500).json({ success: false, error: error.message })
  }
})

// Оплата счёта или налога
billRouter.post('/pay', authenticateToken, async (req, res) => {
  try {
    const { bill_id, tax_bill_id, account_id, amount, otp_code } = req.body || {}

    if (!account_id || !amount) {
      return res.status(400).json({ success: false, error: 'account_id и amount обязательны' })
    }

    const numAmount = Number(amount)
    if (!Number.isFinite(numAmount) || numAmount <= 0) {
      return res.status(400).json({ success: false, error: 'Сумма должна быть больше 0' })
    }

    if (bill_id && tax_bill_id) {
      return res.status(400).json({ 
        success: false, 
        error: 'Нельзя указать одновременно bill_id и tax_bill_id' 
      })
    }

    if (!bill_id && !tax_bill_id) {
      return res.status(400).json({ 
        success: false, 
        error: 'Необходимо указать bill_id или tax_bill_id' 
      })
    }

    if (otp_code !== DEMO_OTP) {
      return res.status(400).json({ success: false, error: 'Неверный код подтверждения' })
    }

    const client = await pool.connect()
    try {
      await client.query('BEGIN')

      const cardRes = await client.query(
        'SELECT balance, user_id, status FROM cards WHERE id = $1',
        [account_id]
      )
      if (cardRes.rows.length === 0) {
        throw new Error('Карта не найдена')
      }
      if (cardRes.rows[0].user_id !== req.user.id) {
        throw new Error('Доступ запрещен')
      }
      if (cardRes.rows[0].status !== 'active') {
        throw new Error('Карта не активна')
      }
      if (Number(cardRes.rows[0].balance) < numAmount) {
        throw new Error('Недостаточно средств')
      }

      const desc = bill_id ? 'Оплата счёта' : 'Оплата налога'
      const txRes = await client.query(
        `INSERT INTO transactions (account_id, counterparty_name, amount, currency, status, description)
         VALUES ($1, $2, $3, 'RUB', 'completed', $4) 
         RETURNING id`,
        [account_id, desc, -numAmount, desc]
      )
      const transactionId = txRes.rows[0].id

      await client.query(
        'UPDATE cards SET balance = balance - $1 WHERE id = $2',
        [numAmount, account_id]
      )

      await client.query(
        `INSERT INTO bill_payments (user_id, bill_id, tax_bill_id, account_id, amount, currency, status, transaction_id, completed_at)
         VALUES ($1, $2, $3, $4, $5, 'RUB', 'completed', $6, NOW())`,
        [req.user.id, bill_id || null, tax_bill_id || null, account_id, numAmount, transactionId]
      )

      if (bill_id) {
        await client.query(
          `UPDATE bills SET status = 'paid', paid_at = NOW() WHERE id = $1`,
          [bill_id]
        )
      } else if (tax_bill_id) {
        await client.query(
          `UPDATE tax_bills SET status = 'paid', paid_at = NOW() WHERE id = $1`,
          [tax_bill_id]
        )
      }

      await client.query('COMMIT')
      res.json({ 
        success: true, 
        message: 'Платеж успешно выполнен', 
        data: { transactionId } 
      })
    } catch (e) {
      await client.query('ROLLBACK')
      throw e
    } finally {
      client.release()
    }
  } catch (error) {
    res.status(500).json({ success: false, error: error.message })
  }
})

// Детали счёта (ПОСЛЕ /find)
billRouter.get('/:id', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT b.*, bp.recipient_name, bp.recipient_address, bp.recipient_phone,
              pr.name as provider_name, pr.category as provider_category
       FROM bills b
       LEFT JOIN bill_profiles bp ON b.bill_profile_id = bp.id
       LEFT JOIN bill_providers pr ON b.provider_id = pr.id
       WHERE b.id = $1 AND (bp.user_id = $2 OR bp.user_id IS NULL)`,
      [req.params.id, req.user.id]
    )
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Счёт не найден' })
    }
    res.json({ success: true, data: result.rows[0] })
  } catch (error) {
    res.status(500).json({ success: false, error: error.message })
  }
})

// =============================================================================
// 6.1. TAX BILLS ROUTES
// =============================================================================

const taxBillRouter = express.Router()

taxBillRouter.get('/', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, tax_type, tax_authority, user_tax_id, assessment_year,
              object_description, object_address,
              assessed_amount, penalty, discount, total_amount, currency,
              status, issue_date, due_date, document_number, created_at, paid_at
       FROM tax_bills
       WHERE user_id = $1
       ORDER BY due_date ASC`,
      [req.user.id]
    )
    res.json({ success: true, data: result.rows })
  } catch (error) {
    res.status(500).json({ success: false, error: error.message })
  }
})

taxBillRouter.get('/:id', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM tax_bills WHERE id = $1 AND user_id = $2`,
      [req.params.id, req.user.id]
    )
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Налоговый счёт не найден' })
    }
    res.json({ success: true, data: result.rows[0] })
  } catch (error) {
    res.status(500).json({ success: false, error: error.message })
  }
})

// =============================================================================
// 7. ATMS ROUTES
// =============================================================================

const atmRouter = express.Router()

atmRouter.get('/', async (req, res) => {
  try {
    const { city, type, limit = '50' } = req.query
    let query = `
      SELECT id, atm_code, bank_name, address, city, country, 
             latitude, longitude, atm_type, services, working_hours, is_24_7
      FROM atm_locations 
      WHERE is_active = true
    `
    const params = []

    if (city) {
      params.push(city)
      query += ` AND LOWER(city) = LOWER($${params.length})`
    }
    if (type) {
      params.push(type)
      query += ` AND atm_type = $${params.length}`
    }

    query += ` ORDER BY city, bank_name LIMIT $${params.length + 1}`
    params.push(parseInt(limit))

    const result = await pool.query(query, params)
    res.json({ success: true, data: result.rows })
  } catch (error) {
    res.status(500).json({ success: false, error: error.message })
  }
})

// =============================================================================
// 8. EXCHANGE RATES ROUTES
// =============================================================================

const exchangeRouter = express.Router()

exchangeRouter.get('/', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT currency_from, currency_to, rate, valid_from, valid_until
       FROM exchange_rates 
       WHERE is_active = true 
         AND (valid_until IS NULL OR valid_until > NOW())
       ORDER BY currency_from, valid_from DESC`
    )

    const uniqueRates = {}
    result.rows.forEach(row => {
      const pair = `${row.currency_from}_${row.currency_to}`
      if (!uniqueRates[pair]) uniqueRates[pair] = row
    })

    res.json({ success: true, data: Object.values(uniqueRates) })
  } catch (error) {
    res.status(500).json({ success: false, error: error.message })
  }
})

// Конвертация валюты
exchangeRouter.post('/', authenticateToken, async (req, res) => {
  try {
    const { from_currency, to_currency, amount } = req.body || {}
    if (!from_currency || !to_currency || !amount) {
      return res.status(400).json({ success: false, error: 'Все поля обязательны' })
    }

    const rateRes = await pool.query(
      `SELECT rate FROM exchange_rates
       WHERE currency_from = $1 AND currency_to = $2
         AND is_active = true AND (valid_until IS NULL OR valid_until > NOW())
       ORDER BY valid_from DESC LIMIT 1`,
      [from_currency, to_currency]
    )

    if (rateRes.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Курс не найден' })
    }

    const rate = parseFloat(rateRes.rows[0].rate)
    const numAmount = parseFloat(amount)
    const converted = numAmount * rate

    res.json({
      success: true,
      data: {
        from_currency,
        to_currency,
        amount: numAmount,
        rate,
        converted_amount: converted,
        timestamp: new Date().toISOString()
      }
    })
  } catch (error) {
    res.status(500).json({ success: false, error: error.message })
  }
})

// =============================================================================
// 9. SAVINGS ROUTES
// =============================================================================

const savingsRouter = express.Router()

// Список депозитов
savingsRouter.get('/', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, account_number, account_type, balance, currency, 
              interest_rate, 
              TO_CHAR(start_date, 'DD/MM/YYYY') as start_date,
              TO_CHAR(end_date, 'DD/MM/YYYY') as end_date,
              EXTRACT(MONTH FROM age(end_date, start_date))::int as term_months,
              status, min_balance, created_at, updated_at
       FROM savings_accounts 
       WHERE user_id = $1 AND status = 'active'
       ORDER BY start_date DESC`,
      [req.user.id]
    )
    res.json({ success: true, data: result.rows })
  } catch (error) {
    res.status(500).json({ success: false, error: error.message })
  }
})

// Создать новый вклад
savingsRouter.post('/', authenticateToken, async (req, res) => {
  try {
    const { account_id, amount, term_months, interest_rate } = req.body || {}
    if (!account_id || !amount || !term_months) {
      return res.status(400).json({ success: false, error: 'account_id, amount и term_months обязательны' })
    }
    const numAmount = Number(amount)
    if (!Number.isFinite(numAmount) || numAmount < 1000) {
      return res.status(400).json({ success: false, error: 'Минимальная сумма вклада: 1000' })
    }

    const client = await pool.connect()
    try {
      await client.query('BEGIN')

      const cardRes = await client.query(
        'SELECT id, balance, user_id, status FROM cards WHERE id = $1',
        [account_id]
      )
      if (cardRes.rows.length === 0) throw new Error('Карта не найдена')
      if (cardRes.rows[0].user_id !== req.user.id) throw new Error('Доступ запрещён')
      if (cardRes.rows[0].status !== 'active') throw new Error('Карта не активна')
      if (Number(cardRes.rows[0].balance) < numAmount) throw new Error('Недостаточно средств')

      const startDate = new Date()
      const endDate = new Date()
      endDate.setMonth(endDate.getMonth() + parseInt(term_months))

      const accRes = await client.query(
        `INSERT INTO savings_accounts (user_id, account_number, account_type, balance, currency, interest_rate,
         start_date, end_date, status, min_balance)
         VALUES ($1, $2, 'deposit', $3, 'RUB', $4, $5, $6, 'active', 1000)
         RETURNING id, account_number, balance, currency, interest_rate,
                   TO_CHAR(start_date, 'DD/MM/YYYY') as start_date,
                   TO_CHAR(end_date, 'DD/MM/YYYY') as end_date`,
        [req.user.id, `DEP-${Date.now()}`, numAmount, interest_rate || 5.0, startDate, endDate]
      )

      await client.query('UPDATE cards SET balance = balance - $1 WHERE id = $2', [numAmount, account_id])

      await client.query(
        `INSERT INTO transactions (account_id, counterparty_name, amount, currency, status, description)
         VALUES ($1, 'Сберегательный счёт', $2, 'RUB', 'completed', 'Открытие вклада')`,
        [account_id, -numAmount]
      )

      await client.query('COMMIT')
      res.status(201).json({ success: true, data: accRes.rows[0] })
    } catch (e) {
      await client.query('ROLLBACK')
      throw e
    } finally {
      client.release()
    }
  } catch (error) {
    res.status(500).json({ success: false, error: error.message })
  }
})

// Детали вклада
savingsRouter.get('/:id', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, account_number, account_type, balance, currency, interest_rate,
              TO_CHAR(start_date, 'DD/MM/YYYY') as start_date,
              TO_CHAR(end_date, 'DD/MM/YYYY') as end_date,
              EXTRACT(MONTH FROM age(end_date, start_date))::int as term_months,
              status, min_balance
       FROM savings_accounts
       WHERE id = $1 AND user_id = $2`,
      [req.params.id, req.user.id]
    )
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Вклад не найден' })
    }
    res.json({ success: true, data: result.rows[0] })
  } catch (error) {
    res.status(500).json({ success: false, error: error.message })
  }
})

// Пополнить вклад
savingsRouter.post('/:id/topup', authenticateToken, async (req, res) => {
  try {
    const { amount, account_id } = req.body || {}
    if (!amount || !account_id) {
      return res.status(400).json({ success: false, error: 'amount и account_id обязательны' })
    }
    const numAmount = Number(amount)
    const client = await pool.connect()
    try {
      await client.query('BEGIN')
      const accRes = await client.query(
        `UPDATE savings_accounts SET balance = balance + $1, updated_at = NOW()
         WHERE id = $2 AND user_id = $3 RETURNING id, balance`,
        [numAmount, req.params.id, req.user.id]
      )
      if (accRes.rows.length === 0) throw new Error('Вклад не найден')
      await client.query('UPDATE cards SET balance = balance - $1 WHERE id = $2 AND user_id = $3', [numAmount, account_id, req.user.id])
      await client.query('COMMIT')
      res.json({ success: true, data: accRes.rows[0] })
    } catch (e) {
      await client.query('ROLLBACK')
      throw e
    } finally {
      client.release()
    }
  } catch (error) {
    res.status(500).json({ success: false, error: error.message })
  }
})

// Снять со вклада
savingsRouter.post('/:id/withdraw', authenticateToken, async (req, res) => {
  try {
    const { amount, account_id } = req.body || {}
    if (!amount || !account_id) {
      return res.status(400).json({ success: false, error: 'amount и account_id обязательны' })
    }
    const numAmount = Number(amount)
    const client = await pool.connect()
    try {
      await client.query('BEGIN')
      const accRes = await client.query(
        `UPDATE savings_accounts SET balance = balance - $1, updated_at = NOW()
         WHERE id = $2 AND user_id = $3 AND balance >= $1 RETURNING id, balance`,
        [numAmount, req.params.id, req.user.id]
      )
      if (accRes.rows.length === 0) throw new Error('Вклад не найден или недостаточно средств')
      await client.query('UPDATE cards SET balance = balance + $1 WHERE id = $2 AND user_id = $3', [numAmount, account_id, req.user.id])
      await client.query('COMMIT')
      res.json({ success: true, data: accRes.rows[0] })
    } catch (e) {
      await client.query('ROLLBACK')
      throw e
    } finally {
      client.release()
    }
  } catch (error) {
    res.status(500).json({ success: false, error: error.message })
  }
})

// =============================================================================
// 10. TRANSFER RECIPIENTS ROUTES (алиас /api/beneficiaries)
// =============================================================================


// =============================================================================
// 11. NOTIFICATIONS ROUTES
// =============================================================================

const notificationRouter = express.Router()

notificationRouter.get('/', authenticateToken, async (req, res) => {
  try {
    const { limit = '50', unread_only } = req.query
    let query = `SELECT id, type, title, body, channel, is_read, read_at, action_url, created_at
                 FROM notifications WHERE user_id = $1`
    const params = [req.user.id]
    if (unread_only === 'true') {
      query += ` AND is_read = FALSE`
    }
    query += ` ORDER BY created_at DESC LIMIT $${params.length + 1}`
    params.push(parseInt(limit))

    const result = await pool.query(query, params)
    res.json({ success: true, data: result.rows })
  } catch (error) {
    res.status(500).json({ success: false, error: error.message })
  }
})

notificationRouter.get('/:id', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM notifications WHERE id = $1 AND user_id = $2`,
      [req.params.id, req.user.id]
    )
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Уведомление не найдено' })
    }
    res.json({ success: true, data: result.rows[0] })
  } catch (error) {
    res.status(500).json({ success: false, error: error.message })
  }
})

notificationRouter.patch('/:id/read', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `UPDATE notifications SET is_read = TRUE, read_at = NOW()
       WHERE id = $1 AND user_id = $2 RETURNING id`,
      [req.params.id, req.user.id]
    )
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Уведомление не найдено' })
    }
    res.json({ success: true })
  } catch (error) {
    res.status(500).json({ success: false, error: error.message })
  }
})

// =============================================================================
// 12. MESSAGES ROUTES
// =============================================================================

const messageRouter = express.Router()

messageRouter.get('/', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT sc.id, sc.subject, sc.status, sc.created_at, sc.closed_at,
              (SELECT COUNT(*) FROM support_messages WHERE conversation_id = sc.id AND sender_id != $1 AND is_read = FALSE)::int as unread_count,
              (SELECT message_text FROM support_messages WHERE conversation_id = sc.id ORDER BY created_at DESC LIMIT 1) as last_message,
              (SELECT created_at FROM support_messages WHERE conversation_id = sc.id ORDER BY created_at DESC LIMIT 1) as last_message_at
       FROM support_conversations sc
       WHERE sc.user_id = $1
       ORDER BY (SELECT MAX(created_at) FROM support_messages WHERE conversation_id = sc.id) DESC`,
      [req.user.id]
    )
    res.json({ success: true, data: result.rows })
  } catch (error) {
    res.status(500).json({ success: false, error: error.message })
  }
})

messageRouter.get('/:id', authenticateToken, async (req, res) => {
  try {
    const convRes = await pool.query(
      `SELECT id FROM support_conversations WHERE id = $1 AND user_id = $2`,
      [req.params.id, req.user.id]
    )
    if (convRes.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Диалог не найден' })
    }

    const result = await pool.query(
      `SELECT sm.id, sm.message_text, sm.sender_id, sm.is_read, sm.created_at,
              u.full_name as sender_name
       FROM support_messages sm
       JOIN users u ON sm.sender_id = u.id
       WHERE sm.conversation_id = $1
       ORDER BY sm.created_at ASC`,
      [req.params.id]
    )

    await pool.query(
      `UPDATE support_messages SET is_read = TRUE
       WHERE conversation_id = $1 AND sender_id != $2 AND is_read = FALSE`,
      [req.params.id, req.user.id]
    )

    res.json({ success: true, data: result.rows })
  } catch (error) {
    res.status(500).json({ success: false, error: error.message })
  }
})

messageRouter.post('/:id', authenticateToken, async (req, res) => {
  try {
    const { message_text } = req.body || {}
    if (!message_text) {
      return res.status(400).json({ success: false, error: 'Текст сообщения обязателен' })
    }

    const convRes = await pool.query(
      `SELECT id FROM support_conversations WHERE id = $1 AND user_id = $2`,
      [req.params.id, req.user.id]
    )
    if (convRes.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Диалог не найден' })
    }

    const result = await pool.query(
      `INSERT INTO support_messages (conversation_id, sender_id, message_text)
       VALUES ($1, $2, $3)
       RETURNING id, message_text, sender_id, created_at`,
      [req.params.id, req.user.id, message_text]
    )

    await pool.query(
      `UPDATE support_conversations SET status = 'in_progress' WHERE id = $1 AND status = 'open'`,
      [req.params.id]
    )

    res.status(201).json({ success: true, data: result.rows[0] })
  } catch (error) {
    res.status(500).json({ success: false, error: error.message })
  }
})

// =============================================================================
// REGISTER ROUTES
// =============================================================================

app.use('/api/auth', authRouter)
app.use('/api/users', userRouter)
app.use('/api/cards', cardRouter)
app.use('/api/transactions', transactionRouter)
app.use('/api/beneficiaries', beneficiaryRouter)
app.use('/api/bills', billRouter)
app.use('/api/tax-bills', taxBillRouter)
app.use('/api/atms', atmRouter)
app.use('/api/exchange-rates', exchangeRouter)
app.use('/api/savings', savingsRouter)
app.use('/api/notifications', notificationRouter)
app.use('/api/messages', messageRouter)

// 404 handler
app.use((req, res) => {
  res.status(404).json({ success: false, error: 'Endpoint not found' })
})

// Global error handler
app.use((err, req, res, next) => {
  console.error('Error:', err.stack)
  res.status(500).json({ success: false, error: 'Внутренняя ошибка сервера' })
})

app.listen(PORT, () => {
  console.log(`🚀 FinPay API запущен на порту ${PORT}`)
  console.log(`📊 Схема БД: ${process.env.DB_SCHEMA || 'public'}`)
  console.log(`🔗 Health check: http://localhost:${PORT}/health`)
})