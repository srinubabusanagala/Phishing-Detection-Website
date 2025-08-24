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
const globals_1 = require("@jest/globals");
const config_1 = __importDefault(require("config"));
const API_URL = 'http://localhost:3000/api';
const REST_URL = 'http://localhost:3000/rest';
const jsonHeader = { 'content-type': 'application/json' };
let authHeader;
describe('/api/Deliverys', () => {
    describe('for regular customer', () => {
        beforeAll(() => {
            return frisby.post(REST_URL + '/user/login', {
                headers: jsonHeader,
                body: {
                    email: 'jim@' + config_1.default.get('application.domain'),
                    password: 'ncc-1701'
                }
            })
                .expect('status', 200)
                .then(({ json }) => {
                authHeader = { Authorization: 'Bearer ' + json.authentication.token, 'content-type': 'application/json' };
            });
        });
        it('GET delivery methods', () => {
            return frisby.get(API_URL + '/Deliverys', { headers: authHeader })
                .expect('status', 200)
                .expect('header', 'content-type', /application\/json/)
                .then(({ json }) => {
                (0, globals_1.expect)(json.data.length).toBe(3);
                (0, globals_1.expect)(json.data[0].id).toBe(1);
                (0, globals_1.expect)(json.data[0].name).toBe('One Day Delivery');
                (0, globals_1.expect)(json.data[0].price).toBe(0.99);
                (0, globals_1.expect)(json.data[0].eta).toBe(1);
            });
        });
    });
    describe('for deluxe customer', () => {
        beforeAll(() => {
            return frisby.post(REST_URL + '/user/login', {
                headers: jsonHeader,
                body: {
                    email: 'ciso@' + config_1.default.get('application.domain'),
                    password: 'mDLx?94T~1CfVfZMzw@sJ9f?s3L6lbMqE70FfI8^54jbNikY5fymx7c!YbJb'
                }
            })
                .expect('status', 200)
                .then(({ json }) => {
                authHeader = { Authorization: 'Bearer ' + json.authentication.token, 'content-type': 'application/json' };
            });
        });
        it('GET delivery methods', () => {
            return frisby.get(API_URL + '/Deliverys', { headers: authHeader })
                .expect('status', 200)
                .expect('header', 'content-type', /application\/json/)
                .then(({ json }) => {
                (0, globals_1.expect)(json.data.length).toBe(3);
                (0, globals_1.expect)(json.data[0].id).toBe(1);
                (0, globals_1.expect)(json.data[0].name).toBe('One Day Delivery');
                (0, globals_1.expect)(json.data[0].price).toBe(0.5);
                (0, globals_1.expect)(json.data[0].eta).toBe(1);
            });
        });
    });
});
describe('/api/Deliverys/:id', () => {
    describe('for regular customer', () => {
        beforeAll(() => {
            return frisby.post(REST_URL + '/user/login', {
                headers: jsonHeader,
                body: {
                    email: 'jim@' + config_1.default.get('application.domain'),
                    password: 'ncc-1701'
                }
            })
                .expect('status', 200)
                .then(({ json }) => {
                authHeader = { Authorization: 'Bearer ' + json.authentication.token, 'content-type': 'application/json' };
            });
        });
        it('GET delivery method', () => {
            return frisby.get(API_URL + '/Deliverys/2', { headers: authHeader })
                .expect('status', 200)
                .expect('header', 'content-type', /application\/json/)
                .then(({ json }) => {
                (0, globals_1.expect)(json.data.id).toBe(2);
                (0, globals_1.expect)(json.data.name).toBe('Fast Delivery');
                (0, globals_1.expect)(json.data.price).toBe(0.5);
                (0, globals_1.expect)(json.data.eta).toBe(3);
            });
        });
    });
    describe('for deluxe customer', () => {
        beforeAll(() => {
            return frisby.post(REST_URL + '/user/login', {
                headers: jsonHeader,
                body: {
                    email: 'ciso@' + config_1.default.get('application.domain'),
                    password: 'mDLx?94T~1CfVfZMzw@sJ9f?s3L6lbMqE70FfI8^54jbNikY5fymx7c!YbJb'
                }
            })
                .expect('status', 200)
                .then(({ json }) => {
                authHeader = { Authorization: 'Bearer ' + json.authentication.token, 'content-type': 'application/json' };
            });
        });
        it('GET delivery method', () => {
            return frisby.get(API_URL + '/Deliverys/2', { headers: authHeader })
                .expect('status', 200)
                .expect('header', 'content-type', /application\/json/)
                .then(({ json }) => {
                (0, globals_1.expect)(json.data.id).toBe(2);
                (0, globals_1.expect)(json.data.name).toBe('Fast Delivery');
                (0, globals_1.expect)(json.data.price).toBe(0);
                (0, globals_1.expect)(json.data.eta).toBe(3);
            });
        });
    });
});
//# sourceMappingURL=deliveryApiSpec.js.map