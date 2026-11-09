require('dotenv').config()
const express = require('express')
const cors = require('cors')
const bcrypt = require('bcryptjs')
const { Pool } = require('pg')
const jwt = require('jsonwebtoken')
const path = require('path')

const app = express()

// ==========================================
// КОНФИГ
// ==========================================
const PORT = Number(process.env.PORT) || 3000
const JWT_SECRET = process.env.JWT_SECRET || process.env.DB_SECRET
const DB_SCHEMA = process.env.DB_SCHEMA || 'public'   // ВАЖНО: латиница, не DB_SСHEMA
const DEMO_OTP = process.env.DEMO_OTP || '123456'     // для демо, в prod — Redis/DB
const CORS_ORIGIN = process.env.CORS_ORIGIN || '*'    // для общего доступа


if (!JWT_SECRET) throw new Error('JWT_SECRET is required')


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
    const { phone, fullName, password } = req.body
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
         VALUES ($1, 'ru', 'RUB')`,
        [userId]
      )

      await client.query('COMMIT')

      const token = jwt.sign({ id: userId, phone }, JWT_SECRET, { expiresIn: '7d' })
      res.status(201).json({ success: true, data: { user: userRes.rows[0], token } })
    } catch (e) {
      await client.query('ROLLBACK')
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
    const { phone, password } = req.body
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
    const { recentPassword, newPassword, confirmPassword } = req.body

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
    const { email, city, country, avatar_url } = req.body
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
    const { status } = req.body
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

// Оплата счёта или налога
billRouter.post('/pay', authenticateToken, async (req, res) => {
  try {
    const { bill_id, tax_bill_id, account_id, amount, otp_code } = req.body

    // Валидация
    if (!account_id || !amount) {
      return res.status(400).json({ success: false, error: 'account_id и amount обязательны' })
    }

    if (amount <= 0) {
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

    // Проверка OTP (DEMO)
    const DEMO_OTP = '123456'
    if (otp_code !== DEMO_OTP) {
      return res.status(400).json({ success: false, error: 'Неверный код подтверждения' })
    }

    const client = await pool.connect()
    try {
      await client.query('BEGIN')

      // Проверка карты и баланса
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
      if (cardRes.rows[0].balance < amount) {
        throw new Error('Недостаточно средств')
      }

      // Создание транзакции
      const desc = bill_id ? 'Оплата счёта' : 'Оплата налога'
      const txRes = await client.query(
        `INSERT INTO transactions (account_id, counterparty_name, amount, currency, status, description)
         VALUES ($1, $2, $3, 'RUB', 'completed', $4) 
         RETURNING id`,
        [account_id, desc, -amount, desc]
      )
      const transactionId = txRes.rows[0].id

      // Списание с карты
      await client.query(
        'UPDATE cards SET balance = balance - $1 WHERE id = $2',
        [amount, account_id]
      )

      // Запись платежа
      await client.query(
        `INSERT INTO bill_payments (user_id, bill_id, tax_bill_id, account_id, amount, currency, status, transaction_id, completed_at)
         VALUES ($1, $2, $3, $4, $5, 'RUB', 'completed', $6, NOW())`,
        [req.user.id, bill_id || null, tax_bill_id || null, account_id, amount, transactionId]
      )

      // Обновление статуса счёта
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

// =============================================================================
// 7. ATMS ROUTES
// =============================================================================

const atmRouter = express.Router()

// Список банкоматов
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

// Курсы валют
exchangeRouter.get('/', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT currency_from, currency_to, rate, valid_from, valid_until
       FROM exchange_rates 
       WHERE is_active = true 
         AND (valid_until IS NULL OR valid_until > NOW())
       ORDER BY currency_from, valid_from DESC`
    )

    // Убираем дубликаты, оставляем только актуальный курс для пары
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

// =============================================================================
// 9. SAVINGS ROUTES (депозиты)
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

// =============================================================================
// REGISTER ROUTES
// =============================================================================

app.use('/api/auth', authRouter)
app.use('/api/users', userRouter)
app.use('/api/cards', cardRouter)
app.use('/api/transactions', transactionRouter)
app.use('/api/bills', billRouter)
app.use('/api/atms', atmRouter)
app.use('/api/exchange-rates', exchangeRouter)
app.use('/api/savings', savingsRouter)

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