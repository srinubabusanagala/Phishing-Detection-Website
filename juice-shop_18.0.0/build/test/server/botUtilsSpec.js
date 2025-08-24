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
const chai_1 = __importDefault(require("chai"));
const botUtils = __importStar(require("../../lib/botUtils"));
const security = __importStar(require("../../lib/insecurity"));
const expect = chai_1.default.expect;
describe('botUtils', () => {
    describe('testFunction', () => {
        it('returns static test response', () => {
            expect(botUtils.testFunction('foo', 'bar')).to.deep.equal({
                action: 'response',
                body: '3be2e438b7f3d04c89d7749f727bb3bd'
            });
        });
    });
    describe('couponCode', () => {
        it('response contains a valid 10% coupon code for current date', () => {
            expect(botUtils.couponCode('foo', 'bar')).to.deep.equal({
                action: 'response',
                body: `Oooookay, if you promise to stop nagging me here's a 10% coupon code for you: ${security.generateCoupon(10, new Date())}`
            });
        });
    });
});
//# sourceMappingURL=botUtilsSpec.js.map