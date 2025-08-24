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
describe('/api/BasketItems', () => {
    it('GET all basket items is forbidden via public API', () => {
        return frisby.get(API_URL + '/BasketItems')
            .expect('status', 401);
    });
    it('POST new basket item is forbidden via public API', () => {
        return frisby.post(API_URL + '/BasketItems', {
            BasketId: 2,
            ProductId: 1,
            quantity: 1
        })
            .expect('status', 401);
    });
    it('GET all basket items', () => {
        return frisby.get(API_URL + '/BasketItems', { headers: authHeader })
            .expect('status', 200);
    });
    it('POST new basket item', () => {
        return frisby.post(API_URL + '/BasketItems', {
            headers: authHeader,
            body: {
                BasketId: 2,
                ProductId: 2,
                quantity: 1
            }
        })
            .expect('status', 200);
    });
    it('POST new basket item with more than available quantity is forbidden', () => {
        return frisby.post(API_URL + '/BasketItems', {
            headers: authHeader,
            body: {
                BasketId: 2,
                ProductId: 2,
                quantity: 101
            }
        })
            .expect('status', 400);
    });
    it('POST new basket item with more than allowed quantity is forbidden', () => {
        return frisby.post(API_URL + '/BasketItems', {
            headers: authHeader,
            body: {
                BasketId: 2,
                ProductId: 1,
                quantity: 6
            }
        })
            .expect('status', 400)
            .expect('json', 'error', 'You can order only up to 5 items of this product.');
    });
});
describe('/api/BasketItems/:id', () => {
    it('GET basket item by id is forbidden via public API', () => {
        return frisby.get(API_URL + '/BasketItems/1')
            .expect('status', 401);
    });
    it('PUT update basket item is forbidden via public API', () => {
        return frisby.put(API_URL + '/BasketItems/1', {
            quantity: 2
        }, { json: true })
            .expect('status', 401);
    });
    it('DELETE basket item is forbidden via public API', () => {
        return frisby.del(API_URL + '/BasketItems/1')
            .expect('status', 401);
    });
    it('GET newly created basket item by id', () => {
        return frisby.post(API_URL + '/BasketItems', {
            headers: authHeader,
            body: {
                BasketId: 2,
                ProductId: 6,
                quantity: 3
            }
        })
            .expect('status', 200)
            .then(({ json }) => {
            return frisby.get(API_URL + '/BasketItems/' + json.data.id, { headers: authHeader })
                .expect('status', 200);
        });
    });
    it('PUT update newly created basket item', () => {
        return frisby.post(API_URL + '/BasketItems', {
            headers: authHeader,
            body: {
                BasketId: 2,
                ProductId: 3,
                quantity: 3
            }
        })
            .expect('status', 200)
            .then(({ json }) => {
            return frisby.put(API_URL + '/BasketItems/' + json.data.id, {
                headers: authHeader,
                body: {
                    quantity: 20
                }
            })
                .expect('status', 200)
                .expect('json', 'data', { quantity: 20 });
        });
    });
    it('PUT update basket ID of basket item is forbidden', () => {
        return frisby.post(API_URL + '/BasketItems', {
            headers: authHeader,
            body: {
                BasketId: 2,
                ProductId: 8,
                quantity: 8
            }
        })
            .expect('status', 200)
            .then(({ json }) => {
            return frisby.put(API_URL + '/BasketItems/' + json.data.id, {
                headers: authHeader,
                body: {
                    BasketId: 42
                }
            })
                .expect('status', 400)
                .expect('json', { message: 'null: `BasketId` cannot be updated due `noUpdate` constraint', errors: [{ field: 'BasketId', message: '`BasketId` cannot be updated due `noUpdate` constraint' }] });
        });
    });
    it('PUT update basket ID of basket item without basket ID', () => {
        return frisby.post(API_URL + '/BasketItems', {
            headers: authHeader,
            body: {
                ProductId: 8,
                quantity: 8
            }
        })
            .expect('status', 200)
            .then(({ json }) => {
            (0, globals_1.expect)(json.data.BasketId).toBeUndefined();
            return frisby.put(API_URL + '/BasketItems/' + json.data.id, {
                headers: authHeader,
                body: {
                    BasketId: 3
                }
            })
                .expect('status', 200)
                .expect('json', 'data', { BasketId: 3 });
        });
    });
    it('PUT update product ID of basket item is forbidden', () => {
        return frisby.post(API_URL + '/BasketItems', {
            headers: authHeader,
            body: {
                BasketId: 2,
                ProductId: 9,
                quantity: 9
            }
        })
            .expect('status', 200)
            .then(({ json }) => {
            return frisby.put(API_URL + '/BasketItems/' + json.data.id, {
                headers: authHeader,
                body: {
                    ProductId: 42
                }
            })
                .expect('status', 400)
                .expect('json', { message: 'null: `ProductId` cannot be updated due `noUpdate` constraint', errors: [{ field: 'ProductId', message: '`ProductId` cannot be updated due `noUpdate` constraint' }] });
        });
    });
    it('PUT update newly created basket item with more than available quantity is forbidden', () => {
        return frisby.post(API_URL + '/BasketItems', {
            headers: authHeader,
            body: {
                BasketId: 2,
                ProductId: 12,
                quantity: 12
            }
        })
            .expect('status', 200)
            .then(({ json }) => {
            return frisby.put(API_URL + '/BasketItems/' + json.data.id, {
                headers: authHeader,
                body: {
                    quantity: 100
                }
            })
                .expect('status', 400);
        });
    });
    it('PUT update basket item with more than allowed quantity is forbidden', () => {
        return frisby.post(API_URL + '/BasketItems', {
            headers: authHeader,
            body: {
                BasketId: 2,
                ProductId: 1,
                quantity: 1
            }
        })
            .expect('status', 200)
            .then(({ json }) => {
            return frisby.put(API_URL + '/BasketItems/' + json.data.id, {
                headers: authHeader,
                body: {
                    quantity: 6
                }
            })
                .expect('status', 400)
                .expect('json', 'error', 'You can order only up to 5 items of this product.');
        });
    });
    it('DELETE newly created basket item', () => {
        return frisby.post(API_URL + '/BasketItems', {
            headers: authHeader,
            body: {
                BasketId: 2,
                ProductId: 10,
                quantity: 10
            }
        })
            .expect('status', 200)
            .then(({ json }) => {
            return frisby.del(API_URL + '/BasketItems/' + json.data.id, { headers: authHeader })
                .expect('status', 200);
        });
    });
});
//# sourceMappingURL=basketItemApiSpec.js.map