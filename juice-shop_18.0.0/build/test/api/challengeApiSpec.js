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
Object.defineProperty(exports, "__esModule", { value: true });
const frisby = __importStar(require("frisby"));
const security = __importStar(require("../../lib/insecurity"));
const Joi = frisby.Joi;
const API_URL = 'http://localhost:3000/api';
const REST_URL = 'http://localhost:3000/rest';
const authHeader = { Authorization: 'Bearer ' + security.authorize(), 'content-type': 'application/json' };
describe('/api/Challenges', () => {
    it('GET all challenges', () => {
        return frisby.get(API_URL + '/Challenges')
            .expect('status', 200)
            .expect('header', 'content-type', /application\/json/)
            .expect('jsonTypes', 'data.*', {
            id: Joi.number(),
            key: Joi.string(),
            name: Joi.string(),
            description: Joi.string(),
            difficulty: Joi.number(),
            solved: Joi.boolean()
        });
    });
    it('POST new challenge is forbidden via public API even when authenticated', () => {
        return frisby.post(API_URL + '/Challenges', {
            headers: authHeader,
            body: {
                name: 'Invulnerability',
                description: 'I am not a vulnerability!',
                difficulty: 3,
                solved: false
            }
        })
            .expect('status', 401);
    });
});
describe('/api/Challenges/:id', () => {
    it('GET existing challenge by id is forbidden via public API even when authenticated', () => {
        return frisby.get(API_URL + '/Challenges/1', { headers: authHeader })
            .expect('status', 401);
    });
    it('PUT update existing challenge is forbidden via public API even when authenticated', () => {
        return frisby.put(API_URL + '/Challenges/1', {
            headers: authHeader,
            body: {
                name: 'Vulnerability',
                description: 'I am a vulnerability!!!',
                difficulty: 3
            }
        })
            .expect('status', 401);
    });
    it('DELETE existing challenge is forbidden via public API even when authenticated', () => {
        return frisby.del(API_URL + '/Challenges/1', { headers: authHeader })
            .expect('status', 401);
    });
});
describe('/rest/continue-code', () => {
    it('GET can retrieve continue code for currently solved challenges', () => {
        return frisby.get(REST_URL + '/continue-code')
            .expect('status', 200);
    });
    it('PUT invalid continue code is rejected (alphanumeric)', () => {
        return frisby.put(REST_URL + '/continue-code/apply/ThisIsDefinitelyNotAValidContinueCode')
            .expect('status', 404);
    });
    it('PUT invalid continue code is rejected (non-alphanumeric)', () => {
        return frisby.put(REST_URL + '/continue-code/apply/%3Cimg%20src=nonexist1%20onerror=alert()%3E')
            .expect('status', 404);
    });
    it('PUT continue code for more than one challenge is accepted', () => {
        return frisby.put(REST_URL + '/continue-code/apply/yXjv6Z5jWJnzD6a3YvmwPRXK7roAyzHDde2Og19yEN84plqxkMBbLVQrDeoY')
            .expect('status', 200);
    });
    it('PUT continue code for non-existent challenge #999 is accepted', () => {
        return frisby.put(REST_URL + '/continue-code/apply/69OxrZ8aJEgxONZyWoz1Dw4BvXmRGkM6Ae9M7k2rK63YpqQLPjnlb5V5LvDj')
            .expect('status', 200);
    });
});
describe('/rest/continue-code-findIt', () => {
    it('GET can retrieve continue code for currently solved challenges', () => {
        return frisby.get(REST_URL + '/continue-code-findIt')
            .expect('status', 200);
    });
    it('PUT invalid continue code is rejected (alphanumeric)', () => {
        return frisby.put(REST_URL + '/continue-code-findIt/apply/ThisIsDefinitelyNotAValidContinueCode')
            .expect('status', 404);
    });
    it('PUT completely invalid continue code is rejected (non-alphanumeric)', () => {
        return frisby.put(REST_URL + '/continue-code-findIt/apply/%3Cimg%20src=nonexist1%20onerror=alert()%3E')
            .expect('status', 404);
    });
    it('PUT continue code for more than one challenge is accepted', () => {
        return frisby.put(REST_URL + '/continue-code-findIt/apply/Xg9oK0VdbW5g1KX9G7JYnqLpz3rAPBh6p4eRlkDM6EaBON2QoPmxjyvwMrP6')
            .expect('status', 200);
    });
});
describe('/rest/continue-code-fixIt', () => {
    it('GET can retrieve continue code for currently solved challenges', () => {
        return frisby.get(REST_URL + '/continue-code-fixIt')
            .expect('status', 200);
    });
    it('PUT invalid continue code is rejected (alphanumeric)', () => {
        return frisby.put(REST_URL + '/continue-code-fixIt/apply/ThisIsDefinitelyNotAValidContinueCode')
            .expect('status', 404);
    });
    it('PUT completely invalid continue code is rejected (non-alphanumeric)', () => {
        return frisby.put(REST_URL + '/continue-code-fixIt/apply/%3Cimg%20src=nonexist1%20onerror=alert()%3E')
            .expect('status', 404);
    });
    it('PUT continue code for more than one challenge is accepted', () => {
        return frisby.put(REST_URL + '/continue-code-fixIt/apply/y28BEPE2k3yRrdz5p6DGqJONnj41n5UEWawYWgBMoVmL79bKZ8Qve0Xl5QLW')
            .expect('status', 200);
    });
});
//# sourceMappingURL=challengeApiSpec.js.map