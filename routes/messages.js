import express from 'express';
import { pool } from '../server.js';
import { authenticateToken } from './auth.js';

const router = express.Router();

// Get all messages for user
router.get('/', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM messages WHERE user_id = $1 ORDER BY created_at ASC',
      [req.user.userId]
    );

    res.json({
      success: true,
      messages: result.rows
    });

  } catch (error) {
    console.error('Get messages error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Send new message
router.post('/', authenticateToken, async (req, res) => {
  try {
    const { message } = req.body;

    if (!message) {
      return res.status(400).json({ error: 'Message is required' });
    }

    // Get user info
    const userResult = await pool.query(
      'SELECT name FROM users WHERE id = $1',
      [req.user.userId]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const userName = userResult.rows[0].name;

    // Insert message
    const result = await pool.query(
      'INSERT INTO messages (user_id, message, sender) VALUES ($1, $2, $3) RETURNING *',
      [req.user.userId, message, 'guest']
    );

    res.json({
      success: true,
      message: 'Message sent successfully',
      message: result.rows[0]
    });

  } catch (error) {
    console.error('Send message error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;
