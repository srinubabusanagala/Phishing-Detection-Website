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
const REST_URL = 'http://localhost:3000/rest';
const jsonHeader = { 'content-type': 'application/json' };
let authHeader;
beforeAll(() => {
    return frisby.post(`${REST_URL}/user/login`, {
        headers: jsonHeader,
        body: {
            email: 'demo',
            password: 'demo'
        }
    })
        .expect('status', 200)
        .then(({ json }) => {
        authHeader = { Authorization: `Bearer ${json.authentication.token}`, 'content-type': 'application/json' };
    });
});
describe('/api/Wallets', () => {
    it('GET wallet is forbidden via public API', () => {
        return frisby.get(`${REST_URL}/wallet/balance`)
            .expect('status', 401);
    });
    it('GET wallet retrieves wallet amount of requesting user', () => {
        return frisby.get(`${REST_URL}/wallet/balance`, {
            headers: authHeader
        })
            .expect('status', 200)
            .expect('header', 'content-type', /application\/json/)
            .expect('json', {
            data: 200
        });
    });
    it('PUT wallet is forbidden via public API', () => {
        return frisby.put(`${REST_URL}/wallet/balance`, {
            body: {
                balance: 10
            }
        })
            .expect('status', 401);
    });
    it('PUT charge wallet from credit card of requesting user', () => {
        return frisby.put(`${REST_URL}/wallet/balance`, {
            headers: authHeader,
            body: {
                balance: 10,
                paymentId: 2
            }
        })
            .expect('status', 200)
            .then(({ json }) => {
            return frisby.get(`${REST_URL}/wallet/balance`, {
                headers: authHeader
            })
                .expect('status', 200)
                .expect('header', 'content-type', /application\/json/)
                .expect('json', {
                data: 210
            });
        });
    });
    it('PUT charge wallet from foreign credit card is forbidden', () => {
        return frisby.put(`${REST_URL}/wallet/balance`, {
            headers: authHeader,
            body: {
                balance: 10,
                paymentId: 1
            }
        })
            .expect('status', 402);
    });
    it('PUT charge wallet without credit card is forbidden', () => {
        return frisby.put(`${REST_URL}/wallet/balance`, {
            headers: authHeader,
            body: {
                balance: 10
            }
        })
            .expect('status', 402);
    });
});
//# sourceMappingURL=walletApiSpec.js.map