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
const REST_URL = 'http://localhost:3000/rest';
const API_URL = 'http://localhost:3000/api';
const jsonHeader = { 'content-type': 'application/json' };
describe('/api/Quantitys', () => {
    it('GET quantity of all items for customers', () => {
        return frisby.post(`${REST_URL}/user/login`, {
            headers: jsonHeader,
            body: {
                email: `jim@${config_1.default.get('application.domain')}`,
                password: 'ncc-1701'
            }
        })
            .expect('status', 200)
            .then(({ json }) => {
            return frisby.get(`${API_URL}/Quantitys`, {
                headers: { Authorization: `Bearer ${json.authentication.token}`, 'content-type': 'application/json' }
            })
                .expect('status', 200);
        });
    });
    it('GET quantity of all items for admin', () => {
        return frisby.post(`${REST_URL}/user/login`, {
            headers: jsonHeader,
            body: {
                email: `admin@${config_1.default.get('application.domain')}`,
                password: 'admin123'
            }
        })
            .expect('status', 200)
            .then(({ json }) => {
            return frisby.get(`${API_URL}/Quantitys`, {
                headers: { Authorization: `Bearer ${json.authentication.token}`, 'content-type': 'application/json' }
            })
                .expect('status', 200);
        });
    });
    it('GET quantity of all items for accounting users', () => {
        return frisby.post(`${REST_URL}/user/login`, {
            headers: jsonHeader,
            body: {
                email: `accountant@${config_1.default.get('application.domain')}`,
                password: 'i am an awesome accountant'
            }
        })
            .expect('status', 200)
            .then(({ json }) => {
            return frisby.get(`${API_URL}/Quantitys`, {
                headers: { Authorization: `Bearer ${json.authentication.token}`, 'content-type': 'application/json' }
            })
                .expect('status', 200);
        });
    });
    it('POST quantity is forbidden for customers', () => {
        return frisby.post(`${REST_URL}/user/login`, {
            headers: jsonHeader,
            body: {
                email: `jim@${config_1.default.get('application.domain')}`,
                password: 'ncc-1701'
            }
        })
            .expect('status', 200)
            .then(({ json }) => {
            return frisby.post(`${API_URL}/Quantitys`, {
                headers: { Authorization: `Bearer ${json.authentication.token}`, 'content-type': 'application/json' },
                body: {
                    ProductId: 1,
                    quantity: 100
                }
            })
                .expect('status', 401);
        });
    });
    it('POST quantity forbidden for admin', () => {
        return frisby.post(`${REST_URL}/user/login`, {
            headers: jsonHeader,
            body: {
                email: `admin@${config_1.default.get('application.domain')}`,
                password: 'admin123'
            }
        })
            .expect('status', 200)
            .then(({ json }) => {
            return frisby.post(`${API_URL}/Quantitys`, {
                headers: { Authorization: `Bearer ${json.authentication.token}`, 'content-type': 'application/json' },
                body: {
                    ProductId: 1,
                    quantity: 100
                }
            })
                .expect('status', 401);
        });
    });
    it('POST quantity is forbidden for accounting users', () => {
        return frisby.post(`${REST_URL}/user/login`, {
            headers: jsonHeader,
            body: {
                email: `accountant@${config_1.default.get('application.domain')}`,
                password: 'i am an awesome accountant'
            }
        })
            .expect('status', 200)
            .then(({ json }) => {
            return frisby.post(`${API_URL}/Quantitys`, {
                headers: { Authorization: `Bearer ${json.authentication.token}`, 'content-type': 'application/json' },
                body: {
                    ProductId: 1,
                    quantity: 100
                }
            })
                .expect('status', 401);
        });
    });
});
describe('/api/Quantitys/:ids', () => {
    it('GET quantity of all items is forbidden for customers', () => {
        return frisby.post(`${REST_URL}/user/login`, {
            headers: jsonHeader,
            body: {
                email: `jim@${config_1.default.get('application.domain')}`,
                password: 'ncc-1701'
            }
        })
            .expect('status', 200)
            .then(({ json }) => {
            return frisby.get(`${API_URL}/Quantitys/1`, {
                headers: { Authorization: `Bearer ${json.authentication.token}`, 'content-type': 'application/json' }
            })
                .expect('status', 403)
                .expect('json', 'error', 'Malicious activity detected');
        });
    });
    it('GET quantity of all items is forbidden for admin', () => {
        return frisby.post(`${REST_URL}/user/login`, {
            headers: jsonHeader,
            body: {
                email: `admin@${config_1.default.get('application.domain')}`,
                password: 'admin123'
            }
        })
            .expect('status', 200)
            .then(({ json }) => {
            return frisby.get(`${API_URL}/Quantitys/1`, {
                headers: { Authorization: `Bearer ${json.authentication.token}`, 'content-type': 'application/json' }
            })
                .expect('status', 403)
                .expect('json', 'error', 'Malicious activity detected');
        });
    });
    it('GET quantity of all items for accounting users blocked by IP filter', () => {
        return frisby.post(`${REST_URL}/user/login`, {
            headers: jsonHeader,
            body: {
                email: `accountant@${config_1.default.get('application.domain')}`,
                password: 'i am an awesome accountant'
            }
        })
            .expect('status', 200)
            .then(({ json }) => {
            return frisby.get(`${API_URL}/Quantitys/1`, {
                headers: { Authorization: `Bearer ${json.authentication.token}`, 'content-type': 'application/json' }
            })
                .expect('status', 403);
        });
    });
    xit('GET quantity of all items for accounting users from IP 123.456.789', () => {
        return frisby.post(`${REST_URL}/user/login`, {
            headers: jsonHeader,
            body: {
                email: `accountant@${config_1.default.get('application.domain')}`,
                password: 'i am an awesome accountant'
            }
        })
            .expect('status', 200)
            .then(({ json }) => {
            return frisby.get(`${API_URL}/Quantitys/1`, {
                headers: { Authorization: `Bearer ${json.authentication.token}`, 'content-type': 'application/json' }
            })
                .expect('status', 200);
        });
    });
    it('PUT quantity is forbidden for customers', () => {
        return frisby.post(`${REST_URL}/user/login`, {
            headers: jsonHeader,
            body: {
                email: `jim@${config_1.default.get('application.domain')}`,
                password: 'ncc-1701'
            }
        })
            .expect('status', 200)
            .then(({ json }) => {
            return frisby.put(`${API_URL}/Quantitys/1`, {
                headers: { Authorization: `Bearer ${json.authentication.token}`, 'content-type': 'application/json' },
                body: {
                    quantity: 100
                }
            })
                .expect('status', 403)
                .expect('json', 'error', 'Malicious activity detected');
        });
    });
    it('PUT quantity is forbidden for admin', () => {
        return frisby.post(`${REST_URL}/user/login`, {
            headers: jsonHeader,
            body: {
                email: `jim@${config_1.default.get('application.domain')}`,
                password: 'ncc-1701'
            }
        })
            .expect('status', 200)
            .then(({ json }) => {
            return frisby.put(`${API_URL}/Quantitys/1`, {
                headers: { Authorization: `Bearer ${json.authentication.token}`, 'content-type': 'application/json' },
                body: {
                    quantity: 100
                }
            })
                .expect('status', 403)
                .expect('json', 'error', 'Malicious activity detected');
        });
    });
    it('PUT quantity as accounting user blocked by IP filter', () => {
        return frisby.post(`${REST_URL}/user/login`, {
            headers: jsonHeader,
            body: {
                email: `accountant@${config_1.default.get('application.domain')}`,
                password: 'i am an awesome accountant'
            }
        })
            .expect('status', 200)
            .then(({ json }) => {
            return frisby.put(`${API_URL}/Quantitys/1`, {
                headers: { Authorization: `Bearer ${json.authentication.token}`, 'content-type': 'application/json' },
                body: {
                    quantity: 100
                }
            })
                .expect('status', 403);
        });
    });
    xit('PUT quantity as accounting user from IP 123.456.789', () => {
        return frisby.post(`${REST_URL}/user/login`, {
            headers: jsonHeader,
            body: {
                email: `accountant@${config_1.default.get('application.domain')}`,
                password: 'i am an awesome accountant'
            }
        })
            .expect('status', 200)
            .then(({ json }) => {
            return frisby.put(`${API_URL}/Quantitys/1`, {
                headers: { Authorization: `Bearer ${json.authentication.token}`, 'content-type': 'application/json' },
                body: {
                    quantity: 100
                }
            })
                .expect('status', 200)
                .then(({ json }) => {
                (0, globals_1.expect)(json.data.quantity).toBe(100);
            });
        });
    });
    it('DELETE quantity is forbidden for accountant', () => {
        return frisby.post(`${REST_URL}/user/login`, {
            headers: jsonHeader,
            body: {
                email: `accountant@${config_1.default.get('application.domain')}`,
                password: 'i am an awesome accountant'
            }
        })
            .expect('status', 200)
            .then(({ json }) => {
            return frisby.del(`${API_URL}/Quantitys/1`, {
                headers: { Authorization: `Bearer ${json.authentication.token}`, 'content-type': 'application/json' }
            })
                .expect('status', 401);
        });
    });
    it('DELETE quantity is forbidden for admin', () => {
        return frisby.post(`${REST_URL}/user/login`, {
            headers: jsonHeader,
            body: {
                email: `admin@${config_1.default.get('application.domain')}`,
                password: 'admin123'
            }
        })
            .expect('status', 200)
            .then(({ json }) => {
            return frisby.del(`${API_URL}/Quantitys/1`, {
                headers: { Authorization: `Bearer ${json.authentication.token}`, 'content-type': 'application/json' }
            })
                .expect('status', 401);
        });
    });
    it('DELETE quantity is forbidden for users', () => {
        return frisby.post(`${REST_URL}/user/login`, {
            headers: jsonHeader,
            body: {
                email: `jim@${config_1.default.get('application.domain')}`,
                password: 'ncc-1701'
            }
        })
            .expect('status', 200)
            .then(({ json }) => {
            return frisby.del(`${API_URL}/Quantitys/1`, {
                headers: { Authorization: `Bearer ${json.authentication.token}`, 'content-type': 'application/json' }
            })
                .expect('status', 401);
        });
    });
});
//# sourceMappingURL=quantityApiSpec.js.map