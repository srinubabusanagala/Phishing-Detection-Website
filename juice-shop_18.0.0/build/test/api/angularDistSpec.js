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
const URL = 'http://localhost:3000';
describe('/api', () => {
    it('GET main.js contains Cryptocurrency URLs', () => {
        return frisby.get(URL + '/main.js')
            .expect('status', 200)
            .expect('bodyContains', '/redirect?to=https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm')
            .expect('bodyContains', '/redirect?to=https://explorer.dash.org/address/Xr556RzuwX6hg5EGpkybbv5RanJoZN17kW')
            .expect('bodyContains', '/redirect?to=https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6');
    });
    it('GET main.js contains password hint for support team', () => {
        return frisby.get(URL + '/main.js')
            .expect('status', 200)
            .expect('bodyContains', 'Parola echipei de asisten\\u021b\\u0103 nu respect\\u0103 politica corporativ\\u0103 pentru conturile privilegiate! V\\u0103 rug\\u0103m s\\u0103 schimba\\u021bi parola \\xeen consecin\\u021b\\u0103!');
    });
});
//# sourceMappingURL=angularDistSpec.js.map