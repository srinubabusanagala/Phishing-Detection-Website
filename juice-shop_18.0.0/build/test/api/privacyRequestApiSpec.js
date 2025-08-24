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
const authHeader = { Authorization: 'Bearer ' + security.authorize(), 'content-type': 'application/json' };
describe('/api/PrivacyRequests', () => {
    it('POST new complaint', () => {
        return frisby.post(API_URL + '/PrivacyRequests', {
            headers: authHeader,
            body: {
                UserId: 1,
                deletionRequested: false
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
    it('GET all privacy requests is forbidden via public API', () => {
        return frisby.get(API_URL + '/PrivacyRequests')
            .expect('status', 401);
    });
});
describe('/api/PrivacyRequests/:id', () => {
    it('GET all privacy requests is forbidden', () => {
        return frisby.get(API_URL + '/PrivacyRequests', { headers: authHeader })
            .expect('status', 401);
    });
    it('GET existing privacy request by id is forbidden', () => {
        return frisby.get(API_URL + '/PrivacyRequests/1', { headers: authHeader })
            .expect('status', 401);
    });
    it('PUT update existing privacy request is forbidden', () => {
        return frisby.put(API_URL + '/PrivacyRequests/1', {
            headers: authHeader,
            body: {
                message: 'Should not work...'
            }
        })
            .expect('status', 401);
    });
    it('DELETE existing privacy request is forbidden', () => {
        return frisby.del(API_URL + '/PrivacyRequests/1', { headers: authHeader })
            .expect('status', 401);
    });
});
//# sourceMappingURL=privacyRequestApiSpec.js.map