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
const API_URL = 'http://localhost:3000/api';
const REST_URL = 'http://localhost:3000/rest';
describe('/api', () => {
    it('GET error when query /api without actual resource', () => {
        return frisby.get(API_URL)
            .expect('status', 500);
    });
});
describe('/rest', () => {
    it('GET error message with information leakage when calling unrecognized path with /rest in it', () => {
        return frisby.get(REST_URL + '/unrecognized')
            .expect('status', 500)
            .expect('bodyContains', '<h1>' + config_1.default.get('application.name') + ' (Express')
            .expect('bodyContains', 'Unexpected path: /rest/unrecognized');
    });
});
//# sourceMappingURL=apiSpec.js.map