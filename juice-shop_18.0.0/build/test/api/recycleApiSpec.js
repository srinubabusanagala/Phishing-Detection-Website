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
const authHeader = { Authorization: `Bearer ${security.authorize()}`, 'content-type': 'application/json' };
describe('/api/Recycles', () => {
    it('POST new recycle', () => {
        return frisby.post(`${API_URL}/Recycles`, {
            headers: authHeader,
            body: {
                quantity: 200,
                AddressId: '1',
                isPickup: true,
                date: '2017-05-31'
            }
        })
            .expect('status', 201)
            .expect('header', 'content-type', /application\/json/)
            .expect('jsonTypes', 'data', {
            id: Joi.number(),
            createdAt: Joi.string(),
            updatedAt: Joi.string()
        });
    });
    it('Will prevent GET all recycles from this endpoint', () => {
        return frisby.get(`${API_URL}/Recycles`)
            .expect('status', 200)
            .expect('header', 'content-type', /application\/json/)
            .expect('jsonTypes', 'data', {
            err: 'Sorry, this endpoint is not supported.'
        });
    });
    it('Will GET existing recycle from this endpoint', () => {
        return frisby.get(`${API_URL}/Recycles/1`)
            .expect('status', 200)
            .expect('header', 'content-type', /application\/json/)
            .expect('jsonTypes', 'data.*', {
            id: Joi.number(),
            UserId: Joi.number(),
            AddressId: Joi.number(),
            quantity: Joi.number(),
            isPickup: Joi.boolean(),
            date: Joi.date(),
            createdAt: Joi.string(),
            updatedAt: Joi.string()
        });
    });
    it('PUT update existing recycle is forbidden', () => {
        return frisby.put(`${API_URL}/Recycles/1`, {
            headers: authHeader,
            body: {
                quantity: 100000
            }
        })
            .expect('status', 401);
    });
    it('DELETE existing recycle is forbidden', () => {
        return frisby.del(`${API_URL}/Recycles/1`, { headers: authHeader })
            .expect('status', 401);
    });
});
//# sourceMappingURL=recycleApiSpec.js.map