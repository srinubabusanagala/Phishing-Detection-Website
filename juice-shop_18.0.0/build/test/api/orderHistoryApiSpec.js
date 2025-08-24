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
const jsonHeader = { 'content-type': 'application/json' };
const REST_URL = 'http://localhost:3000/rest';
describe('/rest/order-history', () => {
    it('GET own previous orders', () => {
        return frisby.post(REST_URL + '/user/login', {
            headers: jsonHeader,
            body: {
                email: 'admin@' + config_1.default.get('application.domain'),
                password: 'admin123'
            }
        })
            .expect('status', 200)
            .then(({ json: jsonLogin }) => {
            return frisby.get(REST_URL + '/order-history', {
                headers: { Authorization: 'Bearer ' + jsonLogin.authentication.token, 'content-type': 'application/json' }
            })
                .expect('status', 200)
                .then(({ json }) => {
                (0, globals_1.expect)(json.data[0].totalPrice).toBe(8.96);
                (0, globals_1.expect)(json.data[0].delivered).toBe(false);
                (0, globals_1.expect)(json.data[0].products[0].quantity).toBe(3);
                (0, globals_1.expect)(json.data[0].products[0].name).toBe('Apple Juice (1000ml)');
                (0, globals_1.expect)(json.data[0].products[0].price).toBe(1.99);
                (0, globals_1.expect)(json.data[0].products[0].total).toBe(5.97);
                (0, globals_1.expect)(json.data[0].products[1].quantity).toBe(1);
                (0, globals_1.expect)(json.data[0].products[1].name).toBe('Orange Juice (1000ml)');
                (0, globals_1.expect)(json.data[0].products[1].price).toBe(2.99);
                (0, globals_1.expect)(json.data[0].products[1].total).toBe(2.99);
                (0, globals_1.expect)(json.data[1].totalPrice).toBe(26.97);
                (0, globals_1.expect)(json.data[1].delivered).toBe(true);
                (0, globals_1.expect)(json.data[1].products[0].quantity).toBe(3);
                (0, globals_1.expect)(json.data[1].products[0].name).toBe('Eggfruit Juice (500ml)');
                (0, globals_1.expect)(json.data[1].products[0].price).toBe(8.99);
                (0, globals_1.expect)(json.data[1].products[0].total).toBe(26.97);
            });
        });
    });
});
describe('/rest/order-history/orders', () => {
    it('GET all orders is forbidden for customers', () => {
        return frisby.post(REST_URL + '/user/login', {
            headers: jsonHeader,
            body: {
                email: 'jim@' + config_1.default.get('application.domain'),
                password: 'ncc-1701'
            }
        })
            .expect('status', 200)
            .then(({ json: jsonLogin }) => {
            return frisby.get(REST_URL + '/order-history/orders', {
                headers: { Authorization: 'Bearer ' + jsonLogin.authentication.token, 'content-type': 'application/json' }
            })
                .expect('status', 403);
        });
    });
    it('GET all orders is forbidden for admin', () => {
        return frisby.post(REST_URL + '/user/login', {
            headers: jsonHeader,
            body: {
                email: 'admin@' + config_1.default.get('application.domain'),
                password: 'admin123'
            }
        })
            .expect('status', 200)
            .then(({ json: jsonLogin }) => {
            return frisby.get(REST_URL + '/order-history/orders', {
                headers: { Authorization: 'Bearer ' + jsonLogin.authentication.token, 'content-type': 'application/json' }
            })
                .expect('status', 403);
        });
    });
    it('GET all orders for accountant', () => {
        return frisby.post(REST_URL + '/user/login', {
            headers: jsonHeader,
            body: {
                email: 'accountant@' + config_1.default.get('application.domain'),
                password: 'i am an awesome accountant'
            }
        })
            .expect('status', 200)
            .then(({ json: jsonLogin }) => {
            return frisby.get(REST_URL + '/order-history/orders', {
                headers: { Authorization: 'Bearer ' + jsonLogin.authentication.token, 'content-type': 'application/json' }
            })
                .expect('status', 200);
        });
    });
});
describe('/rest/order-history/:id/delivery-status', () => {
    it('PUT delivery status is forbidden for admin', () => {
        return frisby.post(REST_URL + '/user/login', {
            headers: jsonHeader,
            body: {
                email: 'admin@' + config_1.default.get('application.domain'),
                password: 'admin123'
            }
        })
            .expect('status', 200)
            .then(({ json: jsonLogin }) => {
            return frisby.put(REST_URL + '/order-history/1/delivery-status', {
                headers: { Authorization: 'Bearer ' + jsonLogin.authentication.token, 'content-type': 'application/json' },
                body: {
                    delivered: false
                }
            })
                .expect('status', 403);
        });
    });
    it('PUT delivery status is forbidden for customer', () => {
        return frisby.post(REST_URL + '/user/login', {
            headers: jsonHeader,
            body: {
                email: 'jim@' + config_1.default.get('application.domain'),
                password: 'ncc-1701'
            }
        })
            .expect('status', 200)
            .then(({ json: jsonLogin }) => {
            return frisby.put(REST_URL + '/order-history/1/delivery-status', {
                headers: { Authorization: 'Bearer ' + jsonLogin.authentication.token, 'content-type': 'application/json' },
                body: {
                    delivered: false
                }
            })
                .expect('status', 403);
        });
    });
    it('PUT delivery status is allowed for accountant', () => {
        return frisby.post(REST_URL + '/user/login', {
            headers: jsonHeader,
            body: {
                email: 'accountant@' + config_1.default.get('application.domain'),
                password: 'i am an awesome accountant'
            }
        })
            .expect('status', 200)
            .then(({ json: jsonLogin }) => {
            return frisby.put(REST_URL + '/order-history/1/delivery-status', {
                headers: { Authorization: 'Bearer ' + jsonLogin.authentication.token, 'content-type': 'application/json' },
                body: {
                    delivered: false
                }
            })
                .expect('status', 200);
        });
    });
});
//# sourceMappingURL=orderHistoryApiSpec.js.map