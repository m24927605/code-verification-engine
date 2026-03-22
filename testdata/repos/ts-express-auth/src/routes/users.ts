import { Router } from 'express';
import { UserService } from '../services/userService';

export const usersRouter = Router();

usersRouter.get('/profile', async (req, res) => {
  const userService = new UserService();
  const user = await userService.findById(req.userId);
  res.json(user);
});

usersRouter.delete('/account', async (req, res) => {
  const userService = new UserService();
  await userService.deleteUser(req.userId);
  res.status(204).send();
});
