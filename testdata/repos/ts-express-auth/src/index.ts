import express from 'express';
import cors from 'cors';
import { authRouter } from './routes/auth';
import { usersRouter } from './routes/users';
import { authMiddleware } from './middleware/auth';

const app = express();

app.use(cors());
app.use(express.json());
app.use(authMiddleware);

app.use('/auth', authRouter);
app.use('/users', usersRouter);

export default app;
