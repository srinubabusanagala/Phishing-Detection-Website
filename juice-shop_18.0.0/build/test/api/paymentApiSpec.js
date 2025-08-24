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
const API_URL = 'http://localhost:3000/api';
const REST_URL = 'http://localhost:3000/rest';
const jsonHeader = { 'content-type': 'application/json' };
let authHeader;
let cardId;
beforeAll(() => {
    return frisby.post(REST_URL + '/user/login', {
        headers: jsonHeader,
        body: {
            email: 'jim@juice-sh.op',
            password: 'ncc-1701'
        }
    })
        .expect('status', 200)
        .then(({ json }) => {
        authHeader = { Authorization: 'Bearer ' + json.authentication.token, 'content-type': 'application/json' };
    });
});
describe('/api/Cards', () => {
    it('GET all cards is forbidden via public API', () => {
        return frisby.get(API_URL + '/Cards')
            .expect('status', 401);
    });
    it('GET all cards', () => {
        return frisby.get(API_URL + '/Cards', { headers: authHeader })
            .expect('status', 200);
    });
    it('POST new card is forbidden via public API', () => {
        return frisby.post(API_URL + '/Cards', {
            fullName: 'Jim',
            cardNum: 12345678876543210,
            expMonth: 1,
            expYear: new Date().getFullYear()
        })
            .expect('status', 401);
    });
    it('POST new card with all valid fields', () => {
        return frisby.post(API_URL + '/Cards', {
            headers: authHeader,
            body: {
                fullName: 'Jim',
                cardNum: 1234567887654321,
                expMonth: 1,
                expYear: 2085
            }
        })
            .expect('status', 201);
    });
    it('POST new card with invalid card number', () => {
        return frisby.post(API_URL + '/Cards', {
            headers: authHeader,
            body: {
                fullName: 'Jim',
                cardNum: 12345678876543210,
                expMonth: 1,
                expYear: new Date().getFullYear()
            }
        })
            .expect('status', 400);
    });
    it('POST new card with invalid expMonth', () => {
        return frisby.post(API_URL + '/Cards', {
            headers: authHeader,
            body: {
                fullName: 'Jim',
                cardNum: 1234567887654321,
                expMonth: 13,
                expYear: new Date().getFullYear()
            }
        })
            .expect('status', 400);
    });
    it('POST new card with invalid expYear', () => {
        return frisby.post(API_URL + '/Cards', {
            headers: authHeader,
            body: {
                fullName: 'Jim',
                cardNum: 1234567887654321,
                expMonth: 1,
                expYear: 2015
            }
        })
            .expect('status', 400);
    });
});
describe('/api/Cards/:id', () => {
    beforeAll(() => {
        return frisby.post(API_URL + '/Cards', {
            headers: authHeader,
            body: {
                fullName: 'Jim',
                cardNum: 1234567887654321,
                expMonth: 1,
                expYear: 2088
            }
        })
            .expect('status', 201)
            .then(({ json }) => {
            cardId = json.data.id;
        });
    });
    it('GET card by id is forbidden via public API', () => {
        return frisby.get(API_URL + '/Cards/' + cardId)
            .expect('status', 401);
    });
    it('PUT update card is forbidden via public API', () => {
        return frisby.put(API_URL + '/Cards/' + cardId, {
            quantity: 2
        }, { json: true })
            .expect('status', 401);
    });
    it('DELETE card by id is forbidden via public API', () => {
        return frisby.del(API_URL + '/Cards/' + cardId)
            .expect('status', 401);
    });
    it('GET card by id', () => {
        return frisby.get(API_URL + '/Cards/' + cardId, { headers: authHeader })
            .expect('status', 200);
    });
    it('PUT update card by id is forbidden via authorized API call', () => {
        return frisby.put(API_URL + '/Cards/' + cardId, {
            headers: authHeader,
            body: {
                fullName: 'Jimy'
            }
        }, { json: true })
            .expect('status', 401);
    });
    it('DELETE card by id', () => {
        return frisby.del(API_URL + '/Cards/' + cardId, { headers: authHeader })
            .expect('status', 200);
    });
});
//# sourceMappingURL=paymentApiSpec.js.map