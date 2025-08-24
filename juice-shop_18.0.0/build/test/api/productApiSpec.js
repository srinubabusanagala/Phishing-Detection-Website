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
const config_1 = __importDefault(require("config"));
const datacache_1 = require("../../data/datacache");
const security = __importStar(require("../../lib/insecurity"));
const utils = __importStar(require("../../lib/utils"));
const Joi = frisby.Joi;
// array index of the items is incremented by one because the db id starts with 1
const tamperingProductId = config_1.default.get('products').findIndex((product) => !!product.urlForProductTamperingChallenge) + 1;
const API_URL = 'http://localhost:3000/api';
const authHeader = { Authorization: 'Bearer ' + security.authorize(), 'content-type': 'application/json' };
const jsonHeader = { 'content-type': 'application/json' };
describe('/api/Products', () => {
    it('GET all products', () => {
        return frisby.get(API_URL + '/Products')
            .expect('status', 200)
            .expect('header', 'content-type', /application\/json/)
            .expect('jsonTypes', 'data.*', {
            id: Joi.number(),
            name: Joi.string(),
            description: Joi.string(),
            price: Joi.number(),
            deluxePrice: Joi.number(),
            image: Joi.string()
        });
    });
    it('POST new product is forbidden via public API', () => {
        return frisby.post(API_URL + '/Products', {
            name: 'Dirt Juice (1000ml)',
            description: 'Made from ugly dirt.',
            price: 0.99,
            image: 'dirt_juice.jpg'
        })
            .expect('status', 401);
    });
    if (utils.isChallengeEnabled(datacache_1.challenges.restfulXssChallenge)) {
        it('POST new product does not filter XSS attacks', () => {
            return frisby.post(API_URL + '/Products', {
                headers: authHeader,
                body: {
                    name: 'XSS Juice (42ml)',
                    description: '<iframe src="javascript:alert(`xss`)">',
                    price: 9999.99,
                    image: 'xss3juice.jpg'
                }
            })
                .expect('header', 'content-type', /application\/json/)
                .expect('json', 'data', { description: '<iframe src="javascript:alert(`xss`)">' });
        });
    }
});
describe('/api/Products/:id', () => {
    it('GET existing product by id', () => {
        return frisby.get(API_URL + '/Products/1')
            .expect('status', 200)
            .expect('header', 'content-type', /application\/json/)
            .expect('jsonTypes', 'data', {
            id: Joi.number(),
            name: Joi.string(),
            description: Joi.string(),
            price: Joi.number(),
            deluxePrice: Joi.number(),
            image: Joi.string(),
            createdAt: Joi.string(),
            updatedAt: Joi.string()
        })
            .expect('json', 'data', { id: 1 });
    });
    it('GET non-existing product by id', () => {
        return frisby.get(API_URL + '/Products/4711')
            .expect('status', 404)
            .expect('header', 'content-type', /application\/json/)
            .expect('json', 'message', 'Not Found');
    });
    it('PUT update existing product is possible due to Missing Function-Level Access Control vulnerability', () => {
        return frisby.put(API_URL + '/Products/' + tamperingProductId, {
            header: jsonHeader,
            body: {
                description: '<a href="http://kimminich.de" target="_blank">More...</a>'
            }
        })
            .expect('status', 200)
            .expect('header', 'content-type', /application\/json/)
            .expect('json', 'data', { description: '<a href="http://kimminich.de" target="_blank">More...</a>' });
    });
    xit('PUT update existing product does not filter XSS attacks', () => {
        return frisby.put(API_URL + '/Products/1', {
            header: jsonHeader,
            body: {
                description: '<script>alert(\'XSS\')</script>'
            }
        })
            .expect('status', 200)
            .expect('header', 'content-type', /application\/json/)
            .expect('json', 'data', { description: '<script>alert(\'XSS\')</script>' });
    });
    it('DELETE existing product is forbidden via public API', () => {
        return frisby.del(API_URL + '/Products/1')
            .expect('status', 401);
    });
    it('DELETE existing product is forbidden via API even when authenticated', () => {
        return frisby.del(API_URL + '/Products/1', { headers: authHeader })
            .expect('status', 401);
    });
});
//# sourceMappingURL=productApiSpec.js.map