const request = require('supertest');
const app = require('./index')

describe('JWKS Server', () => {
    it('should serve JWKS correctly', async () => {
        const res = await request(app).get('/jwks');
        expect(res.statusCode).toEqual(200);
        expect(res.body).toHaveProperty('keys');
        expect(res.body.keys.length).toBeGreaterThan(0);
    });

    it('should issue a JWT on POST to /auth', async () => {
        const res = await request(app).post('/auth');
        expect(res.statusCode).toEqual(200);
        expect(res.body).toHaveProperty('token');

    });


});

