const express = require('express');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const swaggerUi = require('swagger-ui-express');
const swaggerJsdoc = require('swagger-jsdoc');
const cors = require('cors');
const crypto = require('crypto');

function generateUniqueHash() {
    return crypto.randomBytes(3).toString('hex'); // 6 characters
}

// Enable CORS for all origins


require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());

// Database connection
const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

db.getConnection()
    .then(() => console.log('Database connection successful'))
    .catch(err => console.error('Database connection failed:', err));

// JWT Secret
const SECRET = process.env.JWT_SECRET;

const swaggerOptions = {
    definition: {
        openapi: '3.0.0',
        info: { title: 'Food Logs API', version: '1.0.0' },
        components: {
            securitySchemes: {
                BearerAuth: {
                    type: 'http',
                    scheme: 'bearer',
                    bearerFormat: 'JWT',
                }
            },
        },
        security: [{ BearerAuth: [] }],
    },
    apis: ['./index.js'],
};

const specs = swaggerJsdoc(swaggerOptions);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(specs));

const authenticate = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).send('Access denied');
    jwt.verify(token, SECRET, (err, user) => {
        if (err) return res.status(403).send('Invalid token');
        req.user = user;
        next();
    });
};

/**
 * @swagger
 * /register:
 *   post:
 *     summary: Register a new user
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *               password:
 *                 type: string
 */
app.post('/register', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).send('Email and password are required');
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    let uniqueHash;
    let isUnique = false;

    // Ensure hash is unique
    while (!isUnique) {
        uniqueHash = generateUniqueHash();
        const [existing] = await db.query('SELECT * FROM users WHERE hash = ?', [uniqueHash]);
        if (existing.length === 0) isUnique = true;
    }

    try {
        await db.query('INSERT INTO users (email, password, hash) VALUES (?, ?, ?)', 
            [email, hashedPassword, uniqueHash]);
        res.status(201).send({ message: 'User created', hash: uniqueHash });
    } catch (err) {
        console.error('Error during registration:', err);
        res.status(500).send('Internal Server Error');
    }
});

/**
 * @swagger
 * /login:
 *   post:
 *     summary: Authenticate user and return a token
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: Successful login
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 token:
 *                   type: string
 *                 user_id:
 *                   type: integer
 */
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const [users] = await db.query('SELECT id, password, hash FROM users WHERE email = ?', [email]);

        if (users.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const user = users[0];

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign({ user_id: user.id }, process.env.JWT_SECRET, { expiresIn: '24h' });

        res.json({ token, user_id: user.id, hash: user.hash });
    } catch (err) {
        console.error('Error during login:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


/**
 * @swagger
 * /food_logs:
 *   post:
 *     summary: Add a new food log
 *     security:
 *       - BearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [date, name, weight, calories]
 *             properties:
 *               user_id:
 *                 type: integer
 *                 description: User ID (optional, will be taken from JWT if not provided)
 *               date:
 *                 type: string
 *                 format: date
 *               name:
 *                 type: string
 *               weight:
 *                 type: number
 *               calories:
 *                 type: number
 */
app.post('/food_logs', async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        let user_id = req.body.user_id;

        if (!user_id && authHeader) {
            const token = authHeader.split(' ')[1];
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            user_id = decoded.user_id;
        }

        if (!user_id) {
            return res.status(400).json({ error: 'User ID is required' });
        }

        const { date, name, weight, calories } = req.body;

        if (!date || !name || !weight || !calories) {
            return res.status(400).json({ error: 'Missing required fields' });
        }

        const query = 'INSERT INTO food_logs (user_id, date, name, weight, calories) VALUES (?, ?, ?, ?, ?)';
        await db.query(query, [user_id, date, name, weight, calories]);

        res.status(201).json({ message: 'Food log added successfully' });
    } catch (err) {
        console.error('Error adding food log:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});



/**
 * @swagger
 * /food_logs:
 *   get:
 *     summary: Get food logs with optional date filter
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: query
 *         name: user_id
 *         required: true
 *         schema:
 *           type: integer
 *       - in: query
 *         name: date
 *         schema:
 *           type: string
 *           format: date
 *       - in: query
 *         name: start_date
 *         schema:
 *           type: string
 *           format: date
 *       - in: query
 *         name: end_date
 *         schema:
 *           type: string
 *           format: date
 */
app.get('/food_logs', async (req, res) => {
    const { user_id, date, start_date, end_date } = req.query;

    if (!user_id) {
        return res.status(400).json({ error: 'user_id is required' });
    }

    let query = 'SELECT * FROM food_logs WHERE user_id = ?';
    const params = [user_id];

    if (date) {
        query += ' AND date = ?';
        params.push(date);
    } else if (start_date && end_date) {
        query += ' AND date BETWEEN ? AND ?';
        params.push(start_date, end_date);
    }

    try {
        const [logs] = await db.query(query, params);
        res.json(logs);
    } catch (err) {
        console.error('Error fetching food logs:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


/**
 * @swagger
 * /food_logs/{id}:
 *   delete:
 *     summary: Delete a food log entry by ID
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 */
app.delete('/food_logs/:id', authenticate, async (req, res) => {
    await db.query('DELETE FROM food_logs WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    res.status(200).send('Food log deleted');
});

/**
 * @swagger
 * /user_weights:
 *   post:
 *     summary: Add a new weight log
 *     security:
 *       - BearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [date, weight]
 *             properties:
 *               user_id:
 *                 type: integer
 *                 description: User ID (optional, will be taken from JWT if not provided)
 *               date:
 *                 type: string
 *                 format: date
 *               weight:
 *                 type: number
 */
app.post('/user_weights', async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        let user_id = req.body.user_id;

        if (!user_id && authHeader) {
            const token = authHeader.split(' ')[1];
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            user_id = decoded.user_id;
        }

        if (!user_id) {
            return res.status(400).json({ error: 'User ID is required' });
        }

        const { date, weight } = req.body;

        if (!date || !weight) {
            return res.status(400).json({ error: 'Missing required fields' });
        }

        const query = 'INSERT INTO user_weights (user_id, date, weight) VALUES (?, ?, ?)';
        await db.query(query, [user_id, date, weight]);

        res.status(201).json({ message: 'Weight log added successfully' });
    } catch (err) {
        console.error('Error adding weight log:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});



/**
 * @swagger
 * /user_weights/{id}:
 *   delete:
 *     summary: Delete a user weight entry by ID
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 */
app.delete('/user_weights/:id', authenticate, async (req, res) => {
    await db.query('DELETE FROM user_weights WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    res.status(200).send('User weight log deleted');
});

// Public profile access - No JWT required
app.get('/profile/:hash', async (req, res) => {
    const { hash } = req.params;

    try {
        const [user] = await db.query('SELECT email, hash FROM users WHERE hash = ?', [hash]);

        if (user.length === 0) {
            return res.status(404).send('Profile not found');
        }

        res.status(200).json(user[0]);
    } catch (err) {
        console.error('Error fetching profile:', err);
        res.status(500).send('Internal Server Error');
    }
});

app.get('/user_weights', async (req, res) => {
    const { hash, start_date, end_date } = req.query;

    if (!hash) {
        return res.status(400).json({ error: 'hash is required' });
    }

    let query = 'SELECT * FROM user_weights WHERE hash = ?';
    const params = [hash];

    if (start_date && end_date) {
        query += ' AND date BETWEEN ? AND ?';
        params.push(start_date, end_date);
    }

    try {
        const [weights] = await db.query(query, params);
        res.json(weights);
    } catch (err) {
        console.error('Error fetching user weights:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


app.listen(3000, () => console.log('Server running on port 3000'));
