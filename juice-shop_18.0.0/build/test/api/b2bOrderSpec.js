"use strict";
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
/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
const frisby = __importStar(require("frisby"));
const datacache_1 = require("../../data/datacache");
const utils = __importStar(require("../../lib/utils"));
const security = __importStar(require("../../lib/insecurity"));
const Joi = frisby.Joi;
const API_URL = 'http://localhost:3000/b2b/v2/orders';
const authHeader = { Authorization: 'Bearer ' + security.authorize(), 'content-type': 'application/json' };
describe('/b2b/v2/orders', () => {
    if (utils.isChallengeEnabled(datacache_1.challenges.rceChallenge) || utils.isChallengeEnabled(datacache_1.challenges.rceOccupyChallenge)) {
        it('POST endless loop exploit in "orderLinesData" will raise explicit error', () => {
            return frisby.post(API_URL, {
                headers: authHeader,
                body: {
                    orderLinesData: '(function dos() { while(true); })()'
                }
            })
                .expect('status', 500)
                .expect('bodyContains', 'Infinite loop detected - reached max iterations');
        });
        it('POST busy spinning regex attack does not raise an error', () => {
            return frisby.post(API_URL, {
                headers: authHeader,
                body: {
                    orderLinesData: '/((a+)+)b/.test("aaaaaaaaaaaaaaaaaaaaaaaaaaaaa")'
                }
            })
                .expect('status', 503);
        });
        it('POST sandbox breakout attack in "orderLinesData" will raise error', () => {
            return frisby.post(API_URL, {
                headers: authHeader,
                body: {
                    orderLinesData: 'this.constructor.constructor("return process")().exit()'
                }
            })
                .expect('status', 500);
        });
    }
    it('POST new B2B order is forbidden without authorization token', () => {
        return frisby.post(API_URL, {})
            .expect('status', 401);
    });
    it('POST new B2B order accepts arbitrary valid JSON', () => {
        return frisby.post(API_URL, {
            headers: authHeader,
            body: {
                foo: 'bar',
                test: 42
            }
        })
            .expect('status', 200)
            .expect('header', 'content-type', /application\/json/)
            .expect('jsonTypes', {
            cid: Joi.string(),
            orderNo: Joi.string(),
            paymentDue: Joi.string()
        });
    });
    it('POST new B2B order has passed "cid" in response', () => {
        return frisby.post(API_URL, {
            headers: authHeader,
            body: {
                cid: 'test'
            }
        })
            .expect('status', 200)
            .expect('json', {
            cid: 'test'
        });
    });
});
//# sourceMappingURL=b2bOrderSpec.js.map