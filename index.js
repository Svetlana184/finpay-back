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

// ==========================================
// STATIC
// ==========================================
app.use('/uploads/images', express.static(path.join(__dirname, 'uploads/images')))
app.use('/uploads/icons', express.static(path.join(__dirname, 'uploads/icons')))

// ==========================================
// CORS — ОБЩИЙ ДОСТУП
// ==========================================
app.use(cors({
    origin: CORS_ORIGIN,               // '*' — любой домен; или конкретный список
    credentials: true,                 // если нужны cookies
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}))
// preflight для всех маршрутов
app.options('/{*splat}', cors())

app.use(express.json({ limit: '1mb' }))
app.use(express.urlencoded({ extended: true }))

// ==========================================
// POOL
// ==========================================
const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: Number(process.env.DB_PORT) || 5432,
    options: `-c search_path=${DB_SCHEMA}`,
    max: 10,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 5000
})
pool.on('error', (err) => {
    console.error('Unexpected error on idle client', err)
})

// ==========================================
// MIDDLEWARE
// ==========================================
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]

    if (!token) {
        return res.status(401).json({ success: false, error: 'Доступ запрещен: нет токена' })
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ success: false, error: 'Неверный или просроченный токен' })
        if (!user || !user.id) return res.status(403).json({ success: false, error: 'Некорректный токен' })
        req.user = user
        next()
    })
}

// ==========================================
// HEALTH
// ==========================================
app.get('/health', async (req, res) => {
    try {
        await pool.query('SELECT 1')
        res.json({ success: true, status: 'ok', schema: DB_SCHEMA })
    } catch (e) {
        res.status(500).json({ success: false, status: 'db_error', error: e.message })
    }
})

// ==========================================
// ROUTES: AUTH
// ==========================================
const authRouter = express.Router()

authRouter.post('/register', async (req, res, next) => {
    try {
        const { phone, fullName, password } = req.body
        if (!phone || !password) {
            return res.status(400).json({ success: false, error: 'Телефон и пароль обязательны' })
        }
        if (String(password).length < 6) {
            return res.status(400).json({ success: false, error: 'Пароль должен быть не короче 6 символов' })
        }

        const hashedPassword = await bcrypt.hash(String(password), 10)
        const client = await pool.connect()
        try {
            await client.query('BEGIN')

            const userRes = await client.query(
                `INSERT INTO users (phone, full_name, password_hash)
                 VALUES ($1, $2, $3)
                 RETURNING id, phone, full_name`,
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
        next(error)
    }
})

authRouter.post('/login', async (req, res, next) => {
    try {
        const { phone, password } = req.body
        if (!phone || !password) {
            return res.status(400).json({ success: false, error: 'Телефон и пароль обязательны' })
        }

        const result = await pool.query(
            'SELECT id, phone, full_name, password_hash, status FROM users WHERE phone = $1',
            [phone]
        )
        if (result.rows.length === 0) {
            return res.status(401).json({ success: false, error: 'Неверный телефон или пароль' })
        }

        const user = result.rows[0]
        if (user.status !== 'active') {
            return res.status(403).json({ success: false, error: 'Аккаунт заблокирован' })
        }

        const validPassword = await bcrypt.compare(String(password), user.password_hash)
        if (!validPassword) {
            return res.status(401).json({ success: false, error: 'Неверный телефон или пароль' })
        }

        const token = jwt.sign({ id: user.id, phone: user.phone }, JWT_SECRET, { expiresIn: '7d' })
        delete user.password_hash

        res.json({ success: true, data: { user, token } })
    } catch (error) {
        next(error)
    }
})

// ==========================================
// ROUTES: USERS & PROFILES
// ==========================================
const userRouter = express.Router()

userRouter.get('/me', authenticateToken, async (req, res, next) => {
    try {
        const result = await pool.query(
            `SELECT u.id, u.phone, u.full_name, u.status, u.created_at,
                    up.email, up.city, up.country, up.avatar_url, up.is_verified, up.verification_level
             FROM users u
             LEFT JOIN user_profiles up ON u.id = up.user_id
             WHERE u.id = $1`,
            [req.user.id]
        )
        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, error: 'Пользователь не найден' })
        }
        res.json({ success: true, data: result.rows[0] })
    } catch (error) {
        next(error)
    }
})

userRouter.put('/me', authenticateToken, async (req, res, next) => {
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
            [email || null, city || null, country || null, avatar_url || null, req.user.id]
        )
        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, error: 'Профиль не найден' })
        }
        res.json({ success: true, data: result.rows[0] })
    } catch (error) {
        next(error)
    }
})

// ==========================================
// ROUTES: CARDS
// ==========================================
const cardRouter = express.Router()

cardRouter.get('/', authenticateToken, async (req, res, next) => {
    try {
        const result = await pool.query(
            `SELECT id, card_type, RIGHT(card_number, 4) AS last_4_digits,
                    balance, currency, status, expires_at
             FROM cards
             WHERE user_id = $1
             ORDER BY created_at DESC`,
            [req.user.id]
        )
        res.json({ success: true, data: result.rows })
    } catch (error) {
        next(error)
    }
})

cardRouter.patch('/:id/status', authenticateToken, async (req, res, next) => {
    try {
        const { status } = req.body
        if (!['active', 'blocked'].includes(status)) {
            return res.status(400).json({ success: false, error: 'Недопустимый статус' })
        }
        const result = await pool.query(
            `UPDATE cards
             SET status = $1, updated_at = NOW()
             WHERE id = $2 AND user_id = $3
             RETURNING id, card_type, RIGHT(card_number,4) AS last_4_digits, balance, currency, status, expires_at`,
            [status, req.params.id, req.user.id]
        )
        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, error: 'Карта не найдена' })
        }
        res.json({ success: true, data: result.rows[0] })
    } catch (error) {
        next(error)
    }
})

// ==========================================
// ROUTES: TRANSACTIONS
// ==========================================
const transactionRouter = express.Router()

transactionRouter.get('/', authenticateToken, async (req, res, next) => {
    try {
        let { limit = 20, offset = 0, type } = req.query
        limit = Math.min(Math.max(parseInt(limit, 10) || 20, 1), 100)
        offset = Math.max(parseInt(offset, 10) || 0, 0)

        let query = `
            SELECT t.id, t.amount, t.currency, t.status, t.description, t.created_at,
                   t.counterparty_name,
                   c.name AS category_name, c.icon AS category_icon, c.type AS category_type,
                   card.card_type || ' ' || RIGHT(card.card_number, 4) AS card_masked
            FROM transactions t
            JOIN cards card ON t.account_id = card.id
            LEFT JOIN categories c ON t.category_id = c.id
            WHERE card.user_id = $1
        `
        const params = [req.user.id]

        if (type === 'income') {
            query += ` AND t.amount > 0`
        } else if (type === 'expense') {
            query += ` AND t.amount < 0`
        }

        query += ` ORDER BY t.created_at DESC LIMIT $${params.length + 1} OFFSET $${params.length + 2}`
        params.push(limit, offset)

        const result = await pool.query(query, params)
        res.json({ success: true, data: result.rows })
    } catch (error) {
        next(error)
    }
})

// ==========================================
// ROUTES: BILLS & PAYMENTS
// ==========================================
const billRouter = express.Router()

billRouter.get('/profiles', authenticateToken, async (req, res, next) => {
    try {
        const result = await pool.query(
            `SELECT bp.id, bp.profile_name, bp.account_code, bp.recipient_name,
                    pr.name AS provider_name, pr.category, pr.logo_url, bp.is_favorite
             FROM bill_profiles bp
             JOIN bill_providers pr ON bp.provider_id = pr.id
             WHERE bp.user_id = $1
             ORDER BY bp.is_favorite DESC, bp.profile_name`,
            [req.user.id]
        )
        res.json({ success: true, data: result.rows })
    } catch (error) {
        next(error)
    }
})

billRouter.post('/pay', authenticateToken, async (req, res, next) => {
    const client = await pool.connect()
    try {
        const { bill_id, tax_bill_id, account_id, amount, otp_code } = req.body

        // Валидация
        if (!account_id) return res.status(400).json({ success: false, error: 'Не указана карта' })
        if (!amount || Number(amount) <= 0) return res.status(400).json({ success: false, error: 'Некорректная сумма' })
        if (!!bill_id === !!tax_bill_id) {
            return res.status(400).json({ success: false, error: 'Укажите ровно один счёт: bill_id или tax_bill_id' })
        }
        if (otp_code !== DEMO_OTP) {
            return res.status(400).json({ success: false, error: 'Неверный код подтверждения' })
        }

        const payAmount = Number(amount)

        await client.query('BEGIN')

        // 1. Проверка карты и баланса
        const cardRes = await client.query(
            'SELECT balance, currency, user_id FROM cards WHERE id = $1 FOR UPDATE',
            [account_id]
        )
        if (cardRes.rows.length === 0) throw new Error('Карта не найдена')
        const card = cardRes.rows[0]
        if (card.user_id !== req.user.id) throw new Error('Доступ запрещен')
        if (Number(card.balance) < payAmount) throw new Error('Недостаточно средств')

        // 2. Проверка принадлежности счёта пользователю
        if (bill_id) {
            const billRes = await client.query(
                `SELECT b.id FROM bills b
                 JOIN bill_profiles bp ON b.bill_profile_id = bp.id
                 WHERE b.id = $1 AND bp.user_id = $2`,
                [bill_id, req.user.id]
            )
            if (billRes.rows.length === 0) throw new Error('Счёт не найден или не принадлежит пользователю')
        } else {
            const taxRes = await client.query(
                'SELECT id FROM tax_bills WHERE id = $1 AND user_id = $2',
                [tax_bill_id, req.user.id]
            )
            if (taxRes.rows.length === 0) throw new Error('Налог не найден или не принадлежит пользователю')
        }

        // 3. Основная транзакция
        const desc = bill_id ? 'Оплата счета' : 'Оплата налога'
        const txRes = await client.query(
            `INSERT INTO transactions (account_id, counterparty_name, amount, currency, status, description)
             VALUES ($1, $2, $3, $4, 'completed', $5)
             RETURNING id`,
            [account_id, desc, -payAmount, card.currency, desc]
        )
        const transactionId = txRes.rows[0].id

        // 4. Списание с карты
        await client.query(
            'UPDATE cards SET balance = balance - $1, updated_at = NOW() WHERE id = $2',
            [payAmount, account_id]
        )

        // 5. Запись в bill_payments
        await client.query(
            `INSERT INTO bill_payments
                (user_id, bill_id, tax_bill_id, account_id, amount, currency, status, transaction_id, completed_at)
             VALUES ($1, $2, $3, $4, $5, $6, 'completed', $7, NOW())`,
            [req.user.id, bill_id || null, tax_bill_id || null, account_id, payAmount, card.currency, transactionId]
        )

        // 6. Обновление статуса
        if (bill_id) {
            await client.query(`UPDATE bills SET status = 'paid', paid_at = NOW() WHERE id = $1`, [bill_id])
        } else {
            await client.query(`UPDATE tax_bills SET status = 'paid', paid_at = NOW() WHERE id = $1`, [tax_bill_id])
        }

        await client.query('COMMIT')
        res.json({ success: true, message: 'Платеж успешно выполнен', data: { transactionId } })
    } catch (error) {
        await client.query('ROLLBACK').catch(() => {})
        next(error)
    } finally {
        client.release()
    }
})

// ==========================================
// ROUTES: ATMS
// ==========================================
const atmRouter = express.Router()

atmRouter.get('/', async (req, res, next) => {
    try {
        const { city, type } = req.query
        let limit = parseInt(req.query.limit, 10) || 50
        limit = Math.min(Math.max(limit, 1), 200)

        let query = `SELECT id, atm_code, bank_name, address, city, latitude, longitude,
                            atm_type, services, is_24_7
                     FROM atm_locations
                     WHERE is_active = true`
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
        params.push(limit)

        const result = await pool.query(query, params)
        res.json({ success: true, data: result.rows })
    } catch (error) {
        next(error)
    }
})

// ==========================================
// ROUTES: EXCHANGE RATES
// ==========================================
const exchangeRouter = express.Router()

exchangeRouter.get('/', async (req, res, next) => {
    try {
        // DISTINCT ON — самый свежий курс на пару валют
        const result = await pool.query(
            `SELECT DISTINCT ON (currency_from, currency_to)
                    currency_from, currency_to, rate, valid_from
             FROM exchange_rates
             WHERE is_active = true
               AND (valid_until IS NULL OR valid_until > NOW())
             ORDER BY currency_from, currency_to, valid_from DESC`
        )
        res.json({ success: true, data: result.rows })
    } catch (error) {
        next(error)
    }
})

// ==========================================
// REGISTER ROUTES
// ==========================================
app.use('/api/auth', authRouter)
app.use('/api/users', userRouter)
app.use('/api/cards', cardRouter)
app.use('/api/transactions', transactionRouter)
app.use('/api/bills', billRouter)
app.use('/api/atms', atmRouter)
app.use('/api/exchange-rates', exchangeRouter)

// ==========================================
// 404
// ==========================================
app.use((req, res) => {
    res.status(404).json({ success: false, error: 'Маршрут не найден' })
})

// ==========================================
// ГЛОБАЛЬНЫЙ ОБРАБОТЧИК ОШИБОК
// ==========================================
app.use((err, req, res, next) => {
    console.error(err)
    const isProd = process.env.NODE_ENV === 'production'
    res.status(500).json({
        success: false,
        error: isProd ? 'Внутренняя ошибка сервера' : err.message
    })
})

// ==========================================
// START
// ==========================================
app.listen(PORT, () => {
    console.log(`🚀 FinPay API запущен на порту ${PORT}`)
    console.log(`📊 Схема БД: ${DB_SCHEMA}`)
    console.log(`🌐 CORS origin: ${CORS_ORIGIN}`)
})