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
const node_path_1 = __importDefault(require("node:path"));
const node_fs_1 = __importDefault(require("node:fs"));
const URL = 'http://localhost:3000';
const API_URL = 'http://localhost:3000/metrics';
describe('/metrics', () => {
    xit('GET metrics via public API that are available instantaneously', () => {
        return frisby.get(API_URL)
            .expect('status', 200)
            .expect('header', 'content-type', /text\/plain/)
            .expect('bodyContains', /^.*_version_info{version="[0-9]+.[0-9]+.[0-9]+(-SNAPSHOT)?",major="[0-9]+",minor="[0-9]+",patch="[0-9]+",app=".*"} 1$/gm)
            .expect('bodyContains', /^.*_challenges_solved{difficulty="[1-6]",category=".*",app=".*"} [0-9]*$/gm)
            .expect('bodyContains', /^.*_challenges_total{difficulty="[1-6]",category=".*",app=".*"} [0-9]*$/gm)
            .expect('bodyContains', /^.*_cheat_score{app=".*"} [0-9.]*$/gm)
            .expect('bodyContains', /^.*_orders_placed_total{app=".*"} [0-9]*$/gm)
            .expect('bodyContains', /^.*_users_registered{type="standard",app=".*"} [0-9]*$/gm)
            .expect('bodyContains', /^.*_users_registered{type="deluxe",app=".*"} [0-9]*$/gm)
            .expect('bodyContains', /^.*_users_registered_total{app=".*"} [0-9]*$/gm)
            .expect('bodyContains', /^.*_wallet_balance_total{app=".*"} [0-9]*$/gm)
            .expect('bodyContains', /^.*_user_social_interactions{type="review",app=".*"} [0-9]*$/gm)
            .expect('bodyContains', /^.*_user_social_interactions{type="feedback",app=".*"} [0-9]*$/gm)
            .expect('bodyContains', /^.*_user_social_interactions{type="complaint",app=".*"} [0-9]*$/gm)
            .expect('bodyContains', /^http_requests_count{status_code="[0-9]XX",app=".*"} [0-9]*$/gm);
    });
    xit('GET file upload metrics via public API', () => {
        const file = node_path_1.default.resolve(__dirname, '../files/validSizeAndTypeForClient.pdf');
        const form = frisby.formData();
        form.append('file', node_fs_1.default.createReadStream(file)); // casting to blob as the frisby types are wrong and wont accept the fileStream type
        // @ts-expect-error FIXME form.getHeaders() is not found
        return frisby.post(URL + '/file-upload', { headers: { 'Content-Type': form.getHeaders()['content-type'] }, body: form })
            .expect('status', 204)
            .then(() => {
            return frisby.get(API_URL)
                .expect('status', 200)
                .expect('header', 'content-type', /text\/plain/)
                .expect('bodyContains', /^file_uploads_count{file_type=".*",app=".*"} [0-9]*$/gm);
        });
    });
    xit('GET file upload error metrics via public API', () => {
        const file = node_path_1.default.resolve(__dirname, '../files/invalidSizeForServer.pdf');
        const form = frisby.formData();
        form.append('file', node_fs_1.default.createReadStream(file)); // casting to blob as the frisby types are wrong and wont accept the fileStream type
        // @ts-expect-error FIXME form.getHeaders() is not found
        return frisby.post(URL + '/file-upload', { headers: { 'Content-Type': form.getHeaders()['content-type'] }, body: form })
            .expect('status', 500)
            .then(() => {
            return frisby.get(API_URL)
                .expect('status', 200)
                .expect('header', 'content-type', /text\/plain/)
                .expect('bodyContains', /^file_upload_errors{file_type=".*",app=".*"} [0-9]*$/gm);
        });
    });
});
//# sourceMappingURL=metricsApiSpec.js.map