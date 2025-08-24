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
const datacache_1 = require("../../data/datacache");
const utils = __importStar(require("../../lib/utils"));
const globals_1 = require("@jest/globals");
const frisby = __importStar(require("frisby"));
const node_path_1 = __importDefault(require("node:path"));
const node_fs_1 = __importDefault(require("node:fs"));
const URL = 'http://localhost:3000';
describe('/file-upload', () => {
    it('POST file valid PDF for client and API', () => {
        const file = node_path_1.default.resolve(__dirname, '../files/validSizeAndTypeForClient.pdf');
        const form = frisby.formData();
        form.append('file', node_fs_1.default.createReadStream(file)); // casting to blob as the frisby types are wrong and wont accept the fileStream type
        // @ts-expect-error FIXME form.getHeaders() is not found
        return frisby.post(URL + '/file-upload', { headers: { 'Content-Type': form.getHeaders()['content-type'] }, body: form })
            .expect('status', 204);
    });
    it('POST file too large for client validation but valid for API', () => {
        const file = node_path_1.default.resolve(__dirname, '../files/invalidSizeForClient.pdf');
        const form = frisby.formData();
        form.append('file', node_fs_1.default.createReadStream(file)); // casting to blob as the frisby types are wrong and wont accept the fileStream type
        // @ts-expect-error FIXME form.getHeaders() is not found
        return frisby.post(URL + '/file-upload', { headers: { 'Content-Type': form.getHeaders()['content-type'] }, body: form })
            .expect('status', 204);
    });
    it('POST file with illegal type for client validation but valid for API', () => {
        const file = node_path_1.default.resolve(__dirname, '../files/invalidTypeForClient.exe');
        const form = frisby.formData();
        form.append('file', node_fs_1.default.createReadStream(file)); // casting to blob as the frisby types are wrong and wont accept the fileStream type
        // @ts-expect-error FIXME form.getHeaders() is not found
        return frisby.post(URL + '/file-upload', { headers: { 'Content-Type': form.getHeaders()['content-type'] }, body: form })
            .expect('status', 204);
    });
    it('POST file type XML deprecated for API', () => {
        const file = node_path_1.default.resolve(__dirname, '../files/deprecatedTypeForServer.xml');
        const form = frisby.formData();
        form.append('file', node_fs_1.default.createReadStream(file)); // casting to blob as the frisby types are wrong and wont accept the fileStream type
        // @ts-expect-error FIXME form.getHeaders() is not found
        return frisby.post(URL + '/file-upload', { headers: { 'Content-Type': form.getHeaders()['content-type'] }, body: form })
            .expect('status', 410);
    });
    it('POST large XML file near upload size limit', () => {
        const file = node_path_1.default.resolve(__dirname, '../files/maxSizeForServer.xml');
        const form = frisby.formData();
        form.append('file', node_fs_1.default.createReadStream(file)); // casting to blob as the frisby types are wrong and wont accept the fileStream type
        // @ts-expect-error FIXME form.getHeaders() is not found
        return frisby.post(URL + '/file-upload', { headers: { 'Content-Type': form.getHeaders()['content-type'] }, body: form })
            .expect('status', 410);
    });
    if (utils.isChallengeEnabled(datacache_1.challenges.xxeFileDisclosureChallenge) || utils.isChallengeEnabled(datacache_1.challenges.xxeDosChallenge)) {
        it('POST file type XML with XXE attack against Windows', () => {
            const file = node_path_1.default.resolve(__dirname, '../files/xxeForWindows.xml');
            const form = frisby.formData();
            form.append('file', node_fs_1.default.createReadStream(file)); // casting to blob as the frisby types are wrong and wont accept the fileStream type
            return frisby.post(URL + '/file-upload', {
                // @ts-expect-error FIXME form.getHeaders() is not found
                headers: { 'Content-Type': form.getHeaders()['content-type'] },
                body: form
            })
                .expect('status', 410);
        });
        it('POST file type XML with XXE attack against Linux', () => {
            const file = node_path_1.default.resolve(__dirname, '../files/xxeForLinux.xml');
            const form = frisby.formData();
            form.append('file', node_fs_1.default.createReadStream(file)); // casting to blob as the frisby types are wrong and wont accept the fileStream type
            return frisby.post(URL + '/file-upload', {
                // @ts-expect-error FIXME form.getHeaders() is not found
                headers: { 'Content-Type': form.getHeaders()['content-type'] },
                body: form
            })
                .expect('status', 410);
        });
        it('POST file type XML with Billion Laughs attack is caught by parser', () => {
            const file = node_path_1.default.resolve(__dirname, '../files/xxeBillionLaughs.xml');
            const form = frisby.formData();
            form.append('file', node_fs_1.default.createReadStream(file)); // casting to blob as the frisby types are wrong and wont accept the fileStream type
            return frisby.post(URL + '/file-upload', {
                // @ts-expect-error FIXME form.getHeaders() is not found
                headers: { 'Content-Type': form.getHeaders()['content-type'] },
                body: form
            })
                .expect('status', 410)
                .expect('bodyContains', 'Detected an entity reference loop');
        });
        it('POST file type XML with Quadratic Blowup attack', () => {
            const file = node_path_1.default.resolve(__dirname, '../files/xxeQuadraticBlowup.xml');
            const form = frisby.formData();
            form.append('file', node_fs_1.default.createReadStream(file)); // casting to blob as the frisby types are wrong and wont accept the fileStream type
            return frisby.post(URL + '/file-upload', {
                // @ts-expect-error FIXME form.getHeaders() is not found
                headers: { 'Content-Type': form.getHeaders()['content-type'] },
                body: form
            }).then((res) => {
                (0, globals_1.expect)(res.status).toBeGreaterThanOrEqual(410);
            });
        });
        it('POST file type XML with dev/random attack', () => {
            const file = node_path_1.default.resolve(__dirname, '../files/xxeDevRandom.xml');
            const form = frisby.formData();
            form.append('file', node_fs_1.default.createReadStream(file)); // casting to blob as the frisby types are wrong and wont accept the fileStream type
            return frisby.post(URL + '/file-upload', {
                // @ts-expect-error FIXME form.getHeaders() is not found
                headers: { 'Content-Type': form.getHeaders()['content-type'] },
                body: form
            }).then((res) => {
                (0, globals_1.expect)(res.status).toBeGreaterThanOrEqual(410);
            });
        });
    }
    if (utils.isChallengeEnabled(datacache_1.challenges.yamlBombChallenge)) {
        it('POST file type YAML with Billion Laughs-style attack', () => {
            const file = node_path_1.default.resolve(__dirname, '../files/yamlBomb.yml');
            const form = frisby.formData();
            form.append('file', node_fs_1.default.createReadStream(file)); // casting to blob as the frisby types are wrong and wont accept the fileStream type
            return frisby.post(URL + '/file-upload', {
                // @ts-expect-error FIXME form.getHeaders() is not found
                headers: { 'Content-Type': form.getHeaders()['content-type'] },
                body: form
            }).then((res) => {
                (0, globals_1.expect)(res.status).toBeGreaterThanOrEqual(410);
            });
        });
    }
    it('POST file too large for API', () => {
        const file = node_path_1.default.resolve(__dirname, '../files/invalidSizeForServer.pdf');
        const form = frisby.formData();
        form.append('file', node_fs_1.default.createReadStream(file)); // casting to blob as the frisby types are wrong and wont accept the fileStream type
        // @ts-expect-error FIXME form.getHeaders() is not found
        return frisby.post(URL + '/file-upload', { headers: { 'Content-Type': form.getHeaders()['content-type'] }, body: form })
            .expect('status', 500);
    });
    it('POST zip file with directory traversal payload', () => {
        const file = node_path_1.default.resolve(__dirname, '../files/arbitraryFileWrite.zip');
        const form = frisby.formData();
        form.append('file', node_fs_1.default.createReadStream(file)); // casting to blob as the frisby types are wrong and wont accept the fileStream type
        // @ts-expect-error FIXME form.getHeaders() is not found
        return frisby.post(URL + '/file-upload', { headers: { 'Content-Type': form.getHeaders()['content-type'] }, body: form })
            .expect('status', 204);
    });
    it('POST zip file with password protection', () => {
        const file = node_path_1.default.resolve(__dirname, '../files/passwordProtected.zip');
        const form = frisby.formData();
        form.append('file', node_fs_1.default.createReadStream(file)); // casting to blob as the frisby types are wrong and wont accept the fileStream type
        // @ts-expect-error FIXME form.getHeaders() is not found
        return frisby.post(URL + '/file-upload', { headers: { 'Content-Type': form.getHeaders()['content-type'] }, body: form })
            .expect('status', 204);
    });
    xit('POST valid file with tampered content length', () => {
        const file = node_path_1.default.resolve(__dirname, '../files/validSizeAndTypeForClient.pdf');
        const form = frisby.formData();
        form.append('file', node_fs_1.default.createReadStream(file)); // casting to blob as the frisby types are wrong and wont accept the fileStream type
        // @ts-expect-error FIXME form.getHeaders() is not found
        return frisby.post(URL + '/file-upload', { headers: { 'Content-Type': form.getHeaders()['content-type'], 'Content-Length': 42 }, body: form })
            .expect('status', 500)
            .expect('bodyContains', 'Unexpected end of form');
    });
});
//# sourceMappingURL=fileUploadSpec.js.map