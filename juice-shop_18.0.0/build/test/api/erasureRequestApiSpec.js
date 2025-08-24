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
const jsonHeader = { 'content-type': 'application/json' };
const BASE_URL = 'http://localhost:3000';
const REST_URL = 'http://localhost:3000/rest';
describe('/dataerasure', () => {
    it('GET erasure form for logged-in users includes their email and security question', () => {
        return frisby.post(REST_URL + '/user/login', {
            headers: jsonHeader,
            body: {
                email: 'bjoern@owasp.org',
                password: 'kitten lesser pooch karate buffoon indoors'
            }
        })
            .expect('status', 200)
            .then(({ json: jsonLogin }) => {
            return frisby.get(BASE_URL + '/dataerasure/', {
                headers: { Cookie: 'token=' + jsonLogin.authentication.token }
            })
                .expect('status', 200)
                .expect('bodyContains', 'bjoern@owasp.org')
                .expect('bodyContains', 'Name of your favorite pet?');
        });
    });
    it('GET erasure form rendering fails for users without assigned security answer', () => {
        return frisby.post(REST_URL + '/user/login', {
            headers: jsonHeader,
            body: {
                email: 'bjoern.kimminich@gmail.com',
                password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='
            }
        })
            .expect('status', 200)
            .then(({ json: jsonLogin }) => {
            return frisby.get(BASE_URL + '/dataerasure/', {
                headers: { Cookie: 'token=' + jsonLogin.authentication.token }
            })
                .expect('status', 500)
                .expect('bodyContains', 'Error: No answer found!');
        });
    });
    it('GET erasure form rendering fails on unauthenticated access', () => {
        return frisby.get(BASE_URL + '/dataerasure/')
            .expect('status', 500)
            .expect('bodyContains', 'Error: Blocked illegal activity');
    });
    it('POST erasure request does not actually delete the user', () => {
        const form = frisby.formData();
        form.append('email', 'bjoern.kimminich@gmail.com');
        return frisby.post(REST_URL + '/user/login', {
            headers: jsonHeader,
            body: {
                email: 'bjoern.kimminich@gmail.com',
                password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='
            }
        })
            .expect('status', 200)
            .then(({ json: jsonLogin }) => {
            return frisby.post(BASE_URL + '/dataerasure/', {
                headers: { Cookie: 'token=' + jsonLogin.authentication.token },
                body: form
            })
                .expect('status', 200)
                .expect('header', 'Content-Type', 'text/html; charset=utf-8')
                .then(() => {
                return frisby.post(REST_URL + '/user/login', {
                    headers: jsonHeader,
                    body: {
                        email: 'bjoern.kimminich@gmail.com',
                        password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='
                    }
                })
                    .expect('status', 200);
            });
        });
    });
    it('POST erasure form  fails on unauthenticated access', () => {
        return frisby.post(BASE_URL + '/dataerasure/')
            .expect('status', 500)
            .expect('bodyContains', 'Error: Blocked illegal activity');
    });
    it('POST erasure request with empty layout parameter returns', () => {
        return frisby.post(REST_URL + '/user/login', {
            headers: jsonHeader,
            body: {
                email: 'bjoern.kimminich@gmail.com',
                password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='
            }
        })
            .expect('status', 200)
            .then(({ json: jsonLogin }) => {
            return frisby.post(BASE_URL + '/dataerasure/', {
                headers: { Cookie: 'token=' + jsonLogin.authentication.token },
                body: {
                    layout: null
                }
            })
                .expect('status', 200);
        });
    });
    it('POST erasure request with non-existing file path as layout parameter throws error', () => {
        return frisby.post(REST_URL + '/user/login', {
            headers: jsonHeader,
            body: {
                email: 'bjoern.kimminich@gmail.com',
                password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='
            }
        })
            .expect('status', 200)
            .then(({ json: jsonLogin }) => {
            return frisby.post(BASE_URL + '/dataerasure/', {
                headers: { Cookie: 'token=' + jsonLogin.authentication.token },
                body: {
                    layout: '../this/file/does/not/exist'
                }
            })
                .expect('status', 500)
                .expect('bodyContains', 'no such file or directory');
        });
    });
    it('POST erasure request with existing file path as layout parameter returns content truncated', () => {
        return frisby.post(REST_URL + '/user/login', {
            headers: jsonHeader,
            body: {
                email: 'bjoern.kimminich@gmail.com',
                password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='
            }
        })
            .expect('status', 200)
            .then(({ json: jsonLogin }) => {
            return frisby.post(BASE_URL + '/dataerasure/', {
                headers: { Cookie: 'token=' + jsonLogin.authentication.token },
                body: {
                    layout: '../package.json'
                }
            })
                .expect('status', 200)
                .expect('bodyContains', 'juice-shop')
                .expect('bodyContains', '......');
        });
    });
});
//# sourceMappingURL=erasureRequestApiSpec.js.map