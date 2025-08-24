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
describe('/redirect', () => {
    it('GET redirected to https://github.com/juice-shop/juice-shop when this URL is passed as "to" parameter', () => {
        return frisby.get(`${URL}/redirect?to=https://github.com/juice-shop/juice-shop`, { redirect: 'manual' })
            .expect('status', 302);
    });
    it('GET redirected to https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm when this URL is passed as "to" parameter', () => {
        return frisby.get(`${URL}/redirect?to=https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm`, { redirect: 'manual' })
            .expect('status', 302);
    });
    it('GET redirected to http://shop.spreadshirt.com/juiceshop when this URL is passed as "to" parameter', () => {
        return frisby.get(`${URL}/redirect?to=http://shop.spreadshirt.com/juiceshop`, { redirect: 'manual' })
            .expect('status', 302);
    });
    it('GET redirected to http://shop.spreadshirt.de/juiceshop when this URL is passed as "to" parameter', () => {
        return frisby.get(`${URL}/redirect?to=http://shop.spreadshirt.de/juiceshop`, { redirect: 'manual' })
            .expect('status', 302);
    });
    it('GET redirected to https://www.stickeryou.com/products/owasp-juice-shop/794 when this URL is passed as "to" parameter', () => {
        return frisby.get(`${URL}/redirect?to=https://www.stickeryou.com/products/owasp-juice-shop/794`, { redirect: 'manual' })
            .expect('status', 302);
    });
    it('GET redirected to https://explorer.dash.org/address/Xr556RzuwX6hg5EGpkybbv5RanJoZN17kW when this URL is passed as "to" parameter', () => {
        return frisby.get(`${URL}/redirect?to=https://explorer.dash.org/address/Xr556RzuwX6hg5EGpkybbv5RanJoZN17kW`, { redirect: 'manual' })
            .expect('status', 302);
    });
    it('GET redirected to https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6 when this URL is passed as "to" parameter', () => {
        return frisby.get(`${URL}/redirect?to=https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6`, { redirect: 'manual' })
            .expect('status', 302);
    });
    it('GET error message with information leakage when calling /redirect without query parameter', () => {
        return frisby.get(`${URL}/redirect`)
            .expect('status', 500)
            .expect('header', 'content-type', /text\/html/)
            .expect('bodyContains', `<h1>${config_1.default.get('application.name')} (Express`)
            .expect('bodyContains', 'TypeError')
            .expect('bodyContains', 'of undefined')
            .expect('bodyContains', '&#39;includes&#39;');
    });
    it('GET error message with information leakage when calling /redirect with unrecognized query parameter', () => {
        return frisby.get(`${URL}/redirect?x=y`)
            .expect('status', 500)
            .expect('header', 'content-type', /text\/html/)
            .expect('bodyContains', `<h1>${config_1.default.get('application.name')} (Express`)
            .expect('bodyContains', 'TypeError')
            .expect('bodyContains', 'of undefined')
            .expect('bodyContains', '&#39;includes&#39;');
    });
    it('GET error message hinting at allowlist validation when calling /redirect with an unrecognized "to" target', () => {
        return frisby.get(`${URL}/redirect?to=whatever`)
            .expect('status', 406)
            .expect('header', 'content-type', /text\/html/)
            .expect('bodyContains', `<h1>${config_1.default.get('application.name')} (Express`)
            .expect('bodyContains', 'Unrecognized target URL for redirect: whatever');
    });
    it('GET redirected to target URL in "to" parameter when a allow-listed URL is part of the query string', () => {
        return frisby.get(`${URL}/redirect?to=/score-board?satisfyIndexOf=https://github.com/juice-shop/juice-shop`)
            .expect('status', 200)
            .expect('header', 'content-type', /text\/html/)
            .expect('bodyContains', 'main.js')
            .expect('bodyContains', 'runtime.js')
            .expect('bodyContains', 'polyfills.js');
    });
});
//# sourceMappingURL=redirectSpec.js.map