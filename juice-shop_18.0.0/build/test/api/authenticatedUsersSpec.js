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
const security = __importStar(require("../../lib/insecurity"));
const globals_1 = require("@jest/globals");
const config_1 = __importDefault(require("config"));
const REST_URL = 'http://localhost:3000/rest';
const jsonHeader = { ContentType: 'application/json' };
const authHeader = { Authorization: `Bearer ${security.authorize({ data: { email: 'admin@juice-sh.op' } })}`, 'content-type': 'application/json' };
describe('/rest/user/authentication-details', () => {
    it('GET all users with password replaced by asterisks', () => {
        return frisby.get(`${REST_URL}/user/authentication-details`, { headers: authHeader })
            .expect('status', 200)
            .expect('json', 'data.?', {
            password: '********************************'
        });
    });
    it('GET returns lastLoginTime for users with active sessions', async () => {
        await frisby.post(`${REST_URL}/user/login`, {
            headers: jsonHeader,
            body: {
                email: `jim@${config_1.default.get('application.domain')}`,
                password: 'ncc-1701'
            }
        }).promise();
        const response = await frisby.get(`${REST_URL}/user/authentication-details`, { headers: authHeader })
            .expect('status', 200)
            .promise();
        const jim = response.json.data.find((user) => user.email.startsWith('jim@'));
        (0, globals_1.expect)(jim).not.toBe(null);
        (0, globals_1.expect)(jim.lastLoginTime).toEqual(globals_1.expect.any(Number));
    });
});
//# sourceMappingURL=authenticatedUsersSpec.js.map