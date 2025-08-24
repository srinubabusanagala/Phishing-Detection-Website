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
describe('HTTP', () => {
    it('response must contain CORS header allowing all origins', () => {
        return frisby.get(URL)
            .expect('status', 200)
            .expect('header', 'Access-Control-Allow-Origin', '\\*');
    });
    it('response must contain sameorigin frameguard header', () => {
        return frisby.get(URL)
            .expect('status', 200)
            .expect('header', 'X-Frame-Options', 'SAMEORIGIN');
    });
    it('response must contain CORS header allowing all origins', () => {
        return frisby.get(URL)
            .expect('status', 200)
            .expect('header', 'X-Content-Type-Options', 'nosniff');
    });
    it('response must not contain recruiting header', () => {
        return frisby.get(URL)
            .expect('status', 200)
            .expect('header', 'X-Recruiting', config_1.default.get('application.securityTxt.hiring'));
    });
    it('response must not contain XSS protection header', () => {
        return frisby.get(URL)
            .expect('status', 200)
            .expectNot('header', 'X-XSS-Protection');
    });
});
//# sourceMappingURL=httpSpec.js.map