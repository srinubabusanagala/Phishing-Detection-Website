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
const URL = 'http://localhost:3000';
const jsonHeader = { 'content-type': 'application/json' };
let authHeader;
beforeAll(() => {
    return frisby.post(`${URL}/rest/user/login`, {
        headers: jsonHeader,
        body: {
            email: 'jim@juice-sh.op',
            password: 'ncc-1701'
        }
    })
        .expect('status', 200)
        .then(({ json }) => {
        authHeader = { Cookie: `token=${json.authentication.token}` };
    });
});
describe('/profile', () => {
    it('GET user profile is forbidden for unauthenticated user', () => {
        return frisby.get(`${URL}/profile`)
            .expect('status', 500)
            .expect('header', 'content-type', /text\/html/)
            .expect('bodyContains', `<h1>${config_1.default.get('application.name')} (Express`)
            .expect('bodyContains', 'Error: Blocked illegal activity');
    });
    it('GET user profile of authenticated user', () => {
        return frisby.get(`${URL}/profile`, {
            headers: authHeader
        })
            .expect('status', 200)
            .expect('header', 'content-type', /text\/html/)
            .expect('bodyContains', 'id="email" type="email" name="email" value="jim@juice-sh.op"');
    });
    it('POST update username of authenticated user', () => {
        const form = frisby.formData();
        form.append('username', 'Localhorst');
        return frisby.post(`${URL}/profile`, {
            // @ts-expect-error FIXME form.getHeaders() is not found
            headers: { 'Content-Type': form.getHeaders()['content-type'], Cookie: authHeader.Cookie },
            body: form,
            redirect: 'manual'
        })
            .expect('status', 302);
    });
    xit('POST update username is forbidden for unauthenticated user', () => {
        const form = frisby.formData();
        form.append('username', 'Localhorst');
        return frisby.post(`${URL}/profile`, {
            // @ts-expect-error FIXME form.getHeaders() is not found
            headers: { 'Content-Type': form.getHeaders()['content-type'] },
            body: form
        })
            .expect('status', 500)
            .expect('header', 'content-type', /text\/html/)
            .expect('bodyContains', `<h1>${config_1.default.get('application.name')} (Express`)
            .expect('bodyContains', 'Error: Blocked illegal activity');
    });
});
//# sourceMappingURL=userProfileSpec.js.map