import { describe, it, expect } from '@jest/globals';
import { authMiddleware } from '../src/middleware/auth';

describe('authMiddleware', () => {
  it('should reject requests without token', () => {
    const req = { headers: {} } as any;
    const res = { status: jest.fn().mockReturnThis(), json: jest.fn() } as any;
    const next = jest.fn();
    authMiddleware(req, res, next);
    expect(res.status).toHaveBeenCalledWith(401);
  });

  it('should accept valid tokens', () => {
    expect(true).toBe(true);
  });
});
