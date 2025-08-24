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
const API_URL = 'http://localhost:3000/api';
const REST_URL = 'http://localhost:3000/rest';
const jsonHeader = { 'content-type': 'application/json' };
let authHeader;
let addressId;
beforeAll(() => {
    return frisby.post(REST_URL + '/user/login', {
        headers: jsonHeader,
        body: {
            email: 'jim@juice-sh.op',
            password: 'ncc-1701'
        }
    })
        .expect('status', 200)
        .then(({ json }) => {
        authHeader = { Authorization: 'Bearer ' + json.authentication.token, 'content-type': 'application/json' };
    });
});
describe('/api/Addresss', () => {
    it('GET all addresses is forbidden via public API', () => {
        return frisby.get(API_URL + '/Addresss')
            .expect('status', 401);
    });
    it('GET all addresses', () => {
        return frisby.get(API_URL + '/Addresss', { headers: authHeader })
            .expect('status', 200);
    });
    it('POST new address with all valid fields', () => {
        return frisby.post(API_URL + '/Addresss', {
            headers: authHeader,
            body: {
                fullName: 'Jim',
                mobileNum: '9800000000',
                zipCode: 'NX 101',
                streetAddress: 'Bakers Street',
                city: 'NYC',
                state: 'NY',
                country: 'USA'
            }
        })
            .expect('status', 201);
    });
    it('POST new address with invalid pin code', () => {
        return frisby.post(API_URL + '/Addresss', {
            headers: authHeader,
            body: {
                fullName: 'Jim',
                mobileNum: '9800000000',
                zipCode: 'NX 10111111',
                streetAddress: 'Bakers Street',
                city: 'NYC',
                state: 'NY',
                country: 'USA'
            }
        })
            .expect('status', 400);
    });
    it('POST new address with invalid mobile number', () => {
        return frisby.post(API_URL + '/Addresss', {
            headers: authHeader,
            body: {
                fullName: 'Jim',
                mobileNum: '10000000000',
                zipCode: 'NX 101',
                streetAddress: 'Bakers Street',
                city: 'NYC',
                state: 'NY',
                country: 'USA'
            }
        })
            .expect('status', 400);
    });
    it('POST new address is forbidden via public API', () => {
        return frisby.post(API_URL + '/Addresss', {
            fullName: 'Jim',
            mobileNum: '9800000000',
            zipCode: 'NX 10111111',
            streetAddress: 'Bakers Street',
            city: 'NYC',
            state: 'NY',
            country: 'USA'
        })
            .expect('status', 401);
    });
});
describe('/api/Addresss/:id', () => {
    beforeAll(() => {
        return frisby.post(API_URL + '/Addresss', {
            headers: authHeader,
            body: {
                fullName: 'Jim',
                mobileNum: '9800000000',
                zipCode: 'NX 101',
                streetAddress: 'Bakers Street',
                city: 'NYC',
                state: 'NY',
                country: 'USA'
            }
        })
            .expect('status', 201)
            .then(({ json }) => {
            addressId = json.data.id;
        });
    });
    it('GET address by id is forbidden via public API', () => {
        return frisby.get(API_URL + '/Addresss/' + addressId)
            .expect('status', 401);
    });
    it('PUT update address is forbidden via public API', () => {
        return frisby.put(API_URL + '/Addresss/' + addressId, {
            quantity: 2
        }, { json: true })
            .expect('status', 401);
    });
    it('DELETE address by id is forbidden via public API', () => {
        return frisby.del(API_URL + '/Addresss/' + addressId)
            .expect('status', 401);
    });
    it('GET address by id', () => {
        return frisby.get(API_URL + '/Addresss/' + addressId, { headers: authHeader })
            .expect('status', 200);
    });
    it('PUT update address by id', () => {
        return frisby.put(API_URL + '/Addresss/' + addressId, {
            headers: authHeader,
            body: {
                fullName: 'Jimy'
            }
        }, { json: true })
            .expect('status', 200)
            .expect('json', 'data', { fullName: 'Jimy' });
    });
    it('PUT update address by id with invalid mobile number is forbidden', () => {
        return frisby.put(API_URL + '/Addresss/' + addressId, {
            headers: authHeader,
            body: {
                mobileNum: '10000000000'
            }
        }, { json: true })
            .expect('status', 400);
    });
    it('PUT update address by id with invalid pin code is forbidden', () => {
        return frisby.put(API_URL + '/Addresss/' + addressId, {
            headers: authHeader,
            body: {
                zipCode: 'NX 10111111'
            }
        }, { json: true })
            .expect('status', 400);
    });
    it('DELETE address by id', () => {
        return frisby.del(API_URL + '/Addresss/' + addressId, { headers: authHeader })
            .expect('status', 200);
    });
});
//# sourceMappingURL=addressApiSpec.js.map