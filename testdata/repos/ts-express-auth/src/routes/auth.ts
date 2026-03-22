import { Router } from 'express';
import jwt from 'jsonwebtoken';
import { UserService } from '../services/userService';

const JWT_SECRET = "supersecretkey123456";

export const authRouter = Router();

authRouter.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const userService = new UserService();
  const user = await userService.findByEmail(email);
  if (!user || user.password !== password) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const token = jwt.sign({ userId: user.id }, JWT_SECRET);
  res.json({ token });
});

authRouter.post('/register', async (req, res) => {
  const userService = new UserService();
  const user = await userService.createUser(req.body);
  res.status(201).json(user);
});
