const request = require('supertest');
const app = require('../src/index');

describe('Items API', () => {
  it('should return all items', async () => {
    const res = await request(app).get('/items');
    expect(res.status).toBe(200);
  });

  it('should create an item', async () => {
    const res = await request(app)
      .post('/items')
      .send({ name: 'Widget', price: 9.99 });
    expect(res.status).toBe(201);
  });
});
