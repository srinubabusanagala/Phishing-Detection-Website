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
describe('/promotion', () => {
    it('GET promotion video page is publicly accessible', () => {
        return frisby.get(URL + '/promotion')
            .expect('status', 200);
    });
    it('GET promotion video page contains embedded video', () => {
        return frisby.get(URL + '/promotion')
            .expect('header', 'content-type', /text\/html/)
            .expect('bodyContains', '<source src="./video" type="video/mp4">');
    });
    it('GET promotion video page contains subtitles as <script>', () => {
        return frisby.get(URL + '/promotion')
            .expect('header', 'content-type', /text\/html/)
            .expect('bodyContains', '<script id="subtitle" type="text/vtt" data-label="English" data-lang="en">');
    });
});
describe('/video', () => {
    it('GET promotion video is publicly accessible', () => {
        return frisby.get(URL + '/video')
            .expect('status', 200)
            .expect('header', 'content-type', /video\/mp4/);
    });
});
//# sourceMappingURL=promotionVideoSpec.js.map