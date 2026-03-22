const { Router } = require('express');
const { pool } = require('../db/pool');

const itemsRouter = Router();

itemsRouter.get('/', async (req, res) => {
  const result = await pool.query('SELECT * FROM items');
  res.json(result.rows);
});

itemsRouter.post('/', async (req, res) => {
  const { name, price } = req.body;
  const result = await pool.query('INSERT INTO items (name, price) VALUES ($1, $2) RETURNING *', [name, price]);
  res.status(201).json(result.rows[0]);
});

itemsRouter.delete('/:id', async (req, res) => {
  await pool.query('DELETE FROM items WHERE id = $1', [req.params.id]);
  res.status(204).send();
});

exports.itemsRouter = itemsRouter;
