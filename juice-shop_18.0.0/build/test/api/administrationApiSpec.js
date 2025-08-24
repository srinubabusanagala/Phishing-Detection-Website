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
const utils = __importStar(require("../../lib/utils"));
const Joi = frisby.Joi;
const REST_URL = 'http://localhost:3000/rest/admin';
describe('/rest/admin/application-version', () => {
    it('GET application version from package.json', () => {
        return frisby.get(REST_URL + '/application-version')
            .expect('status', 200)
            .expect('header', 'content-type', /application\/json/)
            .expect('json', {
            version: utils.version()
        });
    });
});
describe('/rest/admin/application-configuration', () => {
    it('GET application configuration', () => {
        return frisby.get(REST_URL + '/application-configuration')
            .expect('status', 200)
            .expect('header', 'content-type', /application\/json/)
            .expect('jsonTypes', {
            config: Joi.object()
        });
    });
});
//# sourceMappingURL=administrationApiSpec.js.map