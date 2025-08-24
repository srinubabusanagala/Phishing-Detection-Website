"use strict";
/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const frisby = __importStar(require("frisby"));
const node_http_1 = __importDefault(require("node:http"));
const config_1 = __importDefault(require("config"));
const security = __importStar(require("../../lib/insecurity"));
const Joi = frisby.Joi;
const REST_URL = 'http://localhost:3000/rest';
const jsonHeader = { 'content-type': 'application/json' };
const authHeader = { Authorization: `Bearer ${security.authorize()}`, 'content-type': 'application/json' };
describe('/rest/products/:id/reviews', () => {
    const reviewResponseSchema = {
        id: Joi.number(),
        product: Joi.number(),
        message: Joi.string(),
        author: Joi.string()
    };
    it('GET product reviews by product id', () => {
        return frisby.get(`${REST_URL}/products/1/reviews`)
            .expect('status', 200)
            .expect('header', 'content-type', /application\/json/)
            .expect('jsonTypes', reviewResponseSchema);
    });
    it('GET product reviews attack by injecting a mongoDB sleep command', () => {
        return frisby.get(`${REST_URL}/products/sleep(1)/reviews`)
            .expect('status', 200)
            .expect('header', 'content-type', /application\/json/)
            .expect('jsonTypes', reviewResponseSchema);
    });
    xit('GET product reviews by alphanumeric non-mongoDB-command product id', () => {
        return frisby.get(`${REST_URL}/products/kaboom/reviews`)
            .expect('status', 400);
    });
    it('PUT single product review can be created', () => {
        return frisby.put(`${REST_URL}/products/1/reviews`, {
            body: {
                message: 'Lorem Ipsum',
                author: 'Anonymous'
            }
        })
            .expect('status', 201)
            .expect('header', 'content-type', /application\/json/);
    });
});
describe('/rest/products/reviews', () => {
    const updatedReviewResponseSchema = {
        modified: Joi.number(),
        original: Joi.array(),
        updated: Joi.array()
    };
    let reviewId;
    beforeAll((done) => {
        node_http_1.default.get(`${REST_URL}/products/1/reviews`, (res) => {
            let body = '';
            res.on('data', (chunk) => {
                body += chunk;
            });
            res.on('end', () => {
                const response = JSON.parse(body);
                reviewId = response.data[0]._id;
                done();
            });
        });
    });
    it('PATCH single product review can be edited', () => {
        return frisby.patch(`${REST_URL}/products/reviews`, {
            headers: authHeader,
            body: {
                id: reviewId,
                message: 'Lorem Ipsum'
            }
        })
            .expect('status', 200)
            .expect('header', 'content-type', /application\/json/)
            .expect('jsonTypes', updatedReviewResponseSchema);
    });
    it('PATCH single product review editing need an authenticated user', () => {
        return frisby.patch(`${REST_URL}/products/reviews`, {
            body: {
                id: reviewId,
                message: 'Lorem Ipsum'
            }
        })
            .expect('status', 401);
    });
    it('POST non-existing product review cannot be liked', () => {
        return frisby.post(`${REST_URL}/user/login`, {
            headers: jsonHeader,
            body: {
                email: 'bjoern.kimminich@gmail.com',
                password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='
            }
        })
            .expect('status', 200)
            .then(({ json: jsonLogin }) => {
            return frisby.post(`${REST_URL}/products/reviews`, {
                headers: { Authorization: `Bearer ${jsonLogin.authentication.token}` },
                body: {
                    id: 'does not exist'
                }
            })
                .expect('status', 404);
        });
    });
    it('POST single product review can be liked', () => {
        return frisby.post(`${REST_URL}/user/login`, {
            headers: jsonHeader,
            body: {
                email: 'bjoern.kimminich@gmail.com',
                password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='
            }
        })
            .expect('status', 200)
            .then(({ json: jsonLogin }) => {
            return frisby.post(`${REST_URL}/products/reviews`, {
                headers: { Authorization: `Bearer ${jsonLogin.authentication.token}` },
                body: {
                    id: reviewId
                }
            })
                .expect('status', 200)
                .expect('jsonTypes', { likesCount: Joi.number() });
        });
    });
    it('PATCH multiple product review via injection', () => {
        // Count all the reviews. (Count starts at one because of the review inserted by the other tests...)
        const totalReviews = config_1.default.get('products').reduce((sum, { reviews = [] }) => sum + reviews.length, 1);
        return frisby.patch(`${REST_URL}/products/reviews`, {
            headers: authHeader,
            body: {
                id: { $ne: -1 },
                message: 'trololololololololololololololololololololololololololol'
            }
        })
            .expect('status', 200)
            .expect('header', 'content-type', /application\/json/)
            .expect('jsonTypes', updatedReviewResponseSchema)
            .expect('json', { modified: totalReviews });
    });
});
//# sourceMappingURL=productReviewApiSpec.js.map