import { prisma } from '../db/prisma';

export class UserService {
  async findByEmail(email: string) {
    return await prisma.user.findUnique({ where: { email } });
  }

  async findById(id: string) {
    return await prisma.user.findUnique({ where: { id } });
  }

  async createUser(data: { email: string; password: string; name: string }) {
    return await prisma.user.create({ data });
  }

  async deleteUser(id: string) {
    return await prisma.user.delete({ where: { id } });
  }
}
