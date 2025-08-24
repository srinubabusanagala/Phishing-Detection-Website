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
const jsonHeader = { 'content-type': 'application/json' };
const REST_URL = 'http://localhost:3000/rest';
const API_URL = 'http://localhost:3000/api';
async function login({ email, password }) {
    // @ts-expect-error FIXME promise return handling broken
    const loginRes = await frisby
        .post(`${REST_URL}/user/login`, {
        email,
        password
    }).catch((res) => {
        if (res.json?.type && res.json.status === 'totp_token_required') {
            return res;
        }
        throw new Error(`Failed to login '${email}'`);
    });
    return loginRes.json.authentication;
}
describe('/rest/deluxe-membership', () => {
    it('GET deluxe membership status for customers', () => {
        return frisby.post(REST_URL + '/user/login', {
            headers: jsonHeader,
            body: {
                email: 'bender@' + config_1.default.get('application.domain'),
                password: 'OhG0dPlease1nsertLiquor!'
            }
        })
            .expect('status', 200)
            .then(({ json: jsonLogin }) => {
            return frisby.get(REST_URL + '/deluxe-membership', {
                headers: { Authorization: 'Bearer ' + jsonLogin.authentication.token, 'content-type': 'application/json' }
            })
                .expect('status', 200)
                .expect('json', 'data', { membershipCost: 49 });
        });
    });
    it('GET deluxe membership status for deluxe members throws error', () => {
        return frisby.post(REST_URL + '/user/login', {
            headers: jsonHeader,
            body: {
                email: 'ciso@' + config_1.default.get('application.domain'),
                password: 'mDLx?94T~1CfVfZMzw@sJ9f?s3L6lbMqE70FfI8^54jbNikY5fymx7c!YbJb'
            }
        })
            .expect('status', 200)
            .then(({ json: jsonLogin }) => {
            return frisby.get(REST_URL + '/deluxe-membership', {
                headers: { Authorization: 'Bearer ' + jsonLogin.authentication.token, 'content-type': 'application/json' }
            })
                .expect('status', 400)
                .expect('json', 'error', 'You are already a deluxe member!');
        });
    });
    it('GET deluxe membership status for admin throws error', () => {
        return frisby.post(REST_URL + '/user/login', {
            headers: jsonHeader,
            body: {
                email: 'admin@' + config_1.default.get('application.domain'),
                password: 'admin123'
            }
        })
            .expect('status', 200)
            .then(({ json: jsonLogin }) => {
            return frisby.get(REST_URL + '/deluxe-membership', {
                headers: { Authorization: 'Bearer ' + jsonLogin.authentication.token, 'content-type': 'application/json' }
            })
                .expect('status', 400)
                .expect('json', 'error', 'You are not eligible for deluxe membership!');
        });
    });
    it('GET deluxe membership status for accountant throws error', () => {
        return frisby.post(REST_URL + '/user/login', {
            headers: jsonHeader,
            body: {
                email: 'accountant@' + config_1.default.get('application.domain'),
                password: 'i am an awesome accountant'
            }
        })
            .expect('status', 200)
            .then(({ json: jsonLogin }) => {
            return frisby.get(REST_URL + '/deluxe-membership', {
                headers: { Authorization: 'Bearer ' + jsonLogin.authentication.token, 'content-type': 'application/json' }
            })
                .expect('status', 400)
                .expect('json', 'error', 'You are not eligible for deluxe membership!');
        });
    });
    it('POST upgrade deluxe membership status for customers', async () => {
        const { token } = await login({
            email: `bender@${config_1.default.get('application.domain')}`,
            password: 'OhG0dPlease1nsertLiquor!'
        });
        const { json } = await frisby.get(API_URL + '/Cards', {
            headers: { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }
        })
            .expect('status', 200)
            .promise();
        await frisby.post(REST_URL + '/deluxe-membership', {
            headers: { Authorization: 'Bearer ' + token, 'content-type': 'application/json' },
            body: {
                paymentMode: 'card',
                paymentId: json.data[0].id.toString()
            }
        })
            .expect('status', 200)
            .expect('json', 'status', 'success')
            .promise();
    });
    it('POST deluxe membership status with wrong card id throws error', async () => {
        const { token } = await login({
            email: `jim@${config_1.default.get('application.domain')}`,
            password: 'ncc-1701'
        });
        await frisby.post(REST_URL + '/deluxe-membership', {
            headers: { Authorization: 'Bearer ' + token, 'content-type': 'application/json' },
            body: {
                paymentMode: 'card',
                paymentId: 1337
            }
        })
            .expect('status', 400)
            .expect('json', 'error', 'Invalid Card')
            .promise();
    });
    it('POST deluxe membership status for deluxe members throws error', () => {
        return frisby.post(REST_URL + '/user/login', {
            headers: jsonHeader,
            body: {
                email: 'ciso@' + config_1.default.get('application.domain'),
                password: 'mDLx?94T~1CfVfZMzw@sJ9f?s3L6lbMqE70FfI8^54jbNikY5fymx7c!YbJb'
            }
        })
            .expect('status', 200)
            .then(({ json: jsonLogin }) => {
            return frisby.post(REST_URL + '/deluxe-membership', {
                headers: { Authorization: 'Bearer ' + jsonLogin.authentication.token, 'content-type': 'application/json' },
                body: {
                    paymentMode: 'wallet'
                }
            })
                .expect('status', 400)
                .expect('json', 'error', 'Something went wrong. Please try again!');
        });
    });
    it('POST deluxe membership status for admin throws error', () => {
        return frisby.post(REST_URL + '/user/login', {
            headers: jsonHeader,
            body: {
                email: 'admin@' + config_1.default.get('application.domain'),
                password: 'admin123'
            }
        })
            .expect('status', 200)
            .then(({ json: jsonLogin }) => {
            return frisby.post(REST_URL + '/deluxe-membership', {
                headers: { Authorization: 'Bearer ' + jsonLogin.authentication.token, 'content-type': 'application/json' },
                body: {
                    paymentMode: 'wallet'
                }
            })
                .expect('status', 400)
                .expect('json', 'error', 'Something went wrong. Please try again!');
        });
    });
    it('POST deluxe membership status for accountant throws error', () => {
        return frisby.post(REST_URL + '/user/login', {
            headers: jsonHeader,
            body: {
                email: 'accountant@' + config_1.default.get('application.domain'),
                password: 'i am an awesome accountant'
            }
        })
            .expect('status', 200)
            .then(({ json: jsonLogin }) => {
            return frisby.post(REST_URL + '/deluxe-membership', {
                headers: { Authorization: 'Bearer ' + jsonLogin.authentication.token, 'content-type': 'application/json' },
                body: {
                    paymentMode: 'wallet'
                }
            })
                .expect('status', 400)
                .expect('json', 'error', 'Something went wrong. Please try again!');
        });
    });
});
//# sourceMappingURL=deluxeApiSpec.js.map