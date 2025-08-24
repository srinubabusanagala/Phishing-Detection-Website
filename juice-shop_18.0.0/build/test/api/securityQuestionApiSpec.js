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
const security = __importStar(require("../../lib/insecurity"));
const Joi = frisby.Joi;
const API_URL = 'http://localhost:3000/api';
const REST_URL = 'http://localhost:3000/rest';
const authHeader = { Authorization: `Bearer ${security.authorize()}`, 'content-type': 'application/json' };
describe('/api/SecurityQuestions', () => {
    it('GET all security questions ', () => {
        return frisby.get(`${API_URL}/SecurityQuestions`)
            .expect('status', 200)
            .expect('header', 'content-type', /application\/json/)
            .expect('jsonTypes', 'data.*', {
            id: Joi.number(),
            question: Joi.string()
        });
    });
    it('POST new security question is forbidden via public API even when authenticated', () => {
        return frisby.post(`${API_URL}/SecurityQuestions`, {
            headers: authHeader,
            body: {
                question: 'Your own first name?'
            }
        })
            .expect('status', 401);
    });
});
describe('/api/SecurityQuestions/:id', () => {
    it('GET existing security question by id is forbidden via public API even when authenticated', () => {
        return frisby.get(`${API_URL}/SecurityQuestions/1`, { headers: authHeader })
            .expect('status', 401);
    });
    it('PUT update existing security question is forbidden via public API even when authenticated', () => {
        return frisby.put(`${API_URL}/SecurityQuestions/1`, {
            headers: authHeader,
            body: {
                question: 'Your own first name?'
            }
        })
            .expect('status', 401);
    });
    it('DELETE existing security question is forbidden via public API even when authenticated', () => {
        return frisby.del(`${API_URL}/SecurityQuestions/1`, { headers: authHeader })
            .expect('status', 401);
    });
});
describe('/rest/user/security-question', () => {
    it('GET security question for an existing user\'s email address', () => {
        return frisby.get(`${REST_URL}/user/security-question?email=jim@${config_1.default.get('application.domain')}`)
            .expect('status', 200)
            .expect('json', 'question', {
            question: 'Your eldest siblings middle name?'
        });
    });
    it('GET security question returns nothing for an unknown email address', () => {
        return frisby.get(`${REST_URL}/user/security-question?email=horst@unknown-us.er`)
            .expect('status', 200)
            .expect('json', {});
    });
    it('GET security question throws error for missing email address', () => {
        return frisby.get(`${REST_URL}/user/security-question`)
            .expect('status', 500)
            .expect('header', 'content-type', /text\/html/)
            .expect('bodyContains', `<h1>${config_1.default.get('application.name')} (Express`)
            .expect('bodyContains', 'Error: WHERE parameter &quot;email&quot; has invalid &quot;undefined&quot; value');
    });
    it('GET security question is not susceptible to SQL Injection attacks', () => {
        return frisby.get(`${REST_URL}/user/security-question?email=';`)
            .expect('status', 200);
    });
});
//# sourceMappingURL=securityQuestionApiSpec.js.map