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
const node_path_1 = __importDefault(require("node:path"));
const node_fs_1 = __importDefault(require("node:fs"));
const jsonHeader = { 'content-type': 'application/json' };
const REST_URL = 'http://localhost:3000/rest';
const URL = 'http://localhost:3000';
describe('/profile/image/file', () => {
    it('POST profile image file valid for JPG format', () => {
        const file = node_path_1.default.resolve(__dirname, '../files/validProfileImage.jpg');
        const form = frisby.formData();
        form.append('file', node_fs_1.default.createReadStream(file)); // casting to blob as the frisby types are wrong and wont accept the fileStream type
        return frisby.post(`${REST_URL}/user/login`, {
            headers: jsonHeader,
            body: {
                email: `jim@${config_1.default.get('application.domain')}`,
                password: 'ncc-1701'
            }
        })
            .expect('status', 200)
            .then(({ json: jsonLogin }) => {
            return frisby.post(`${URL}/profile/image/file`, {
                headers: {
                    Cookie: `token=${jsonLogin.authentication.token}`,
                    // @ts-expect-error FIXME form.getHeaders() is not found
                    'Content-Type': form.getHeaders()['content-type']
                },
                body: form,
                redirect: 'manual'
            })
                .expect('status', 302);
        });
    });
    it('POST profile image file invalid type', () => {
        const file = node_path_1.default.resolve(__dirname, '../files/invalidProfileImageType.docx');
        const form = frisby.formData();
        form.append('file', node_fs_1.default.createReadStream(file)); // casting to blob as the frisby types are wrong and wont accept the fileStream type
        return frisby.post(`${REST_URL}/user/login`, {
            headers: jsonHeader,
            body: {
                email: `jim@${config_1.default.get('application.domain')}`,
                password: 'ncc-1701'
            }
        })
            .expect('status', 200)
            .then(({ json: jsonLogin }) => {
            return frisby.post(`${URL}/profile/image/file`, {
                headers: {
                    Cookie: `token=${jsonLogin.authentication.token}`,
                    // @ts-expect-error FIXME form.getHeaders() is not found
                    'Content-Type': form.getHeaders()['content-type']
                },
                body: form
            })
                .expect('status', 415)
                .expect('header', 'content-type', /text\/html/)
                .expect('bodyContains', `<h1>${config_1.default.get('application.name')} (Express`)
                .expect('bodyContains', 'Error: Profile image upload does not accept this file type');
        });
    });
    it('POST profile image file forbidden for anonymous user', () => {
        const file = node_path_1.default.resolve(__dirname, '../files/validProfileImage.jpg');
        const form = frisby.formData();
        form.append('file', node_fs_1.default.createReadStream(file)); // casting to blob as the frisby types are wrong and wont accept the fileStream type
        return frisby.post(`${URL}/profile/image/file`, {
            // @ts-expect-error FIXME form.getHeaders() is not found
            headers: { 'Content-Type': form.getHeaders()['content-type'] },
            body: form
        })
            .expect('status', 500)
            .expect('header', 'content-type', /text\/html/)
            .expect('bodyContains', 'Error: Blocked illegal activity');
    });
});
describe('/profile/image/url', () => {
    it('POST profile image URL valid for image available online', () => {
        const form = frisby.formData();
        form.append('imageUrl', 'cataas.com/cat');
        return frisby.post(`${REST_URL}/user/login`, {
            headers: jsonHeader,
            body: {
                email: `jim@${config_1.default.get('application.domain')}`,
                password: 'ncc-1701'
            }
        })
            .expect('status', 200)
            .then(({ json: jsonLogin }) => {
            return frisby.post(`${URL}/profile/image/url`, {
                headers: {
                    Cookie: `token=${jsonLogin.authentication.token}`,
                    // @ts-expect-error FIXME form.getHeaders() is not found
                    'Content-Type': form.getHeaders()['content-type']
                },
                body: form,
                redirect: 'manual'
            })
                .expect('status', 302);
        });
    });
    it('POST profile image URL redirects even for invalid image URL', () => {
        const form = frisby.formData();
        form.append('imageUrl', 'https://notanimage.here/100/100');
        return frisby.post(`${REST_URL}/user/login`, {
            headers: jsonHeader,
            body: {
                email: `jim@${config_1.default.get('application.domain')}`,
                password: 'ncc-1701'
            }
        })
            .expect('status', 200)
            .then(({ json: jsonLogin }) => {
            return frisby.post(`${URL}/profile/image/url`, {
                headers: {
                    Cookie: `token=${jsonLogin.authentication.token}`,
                    // @ts-expect-error FIXME form.getHeaders() is not found
                    'Content-Type': form.getHeaders()['content-type']
                },
                body: form,
                redirect: 'manual'
            })
                .expect('status', 302);
        });
    });
    xit('POST profile image URL forbidden for anonymous user', () => {
        const form = frisby.formData();
        form.append('imageUrl', 'cataas.com/cat');
        return frisby.post(`${URL}/profile/image/url`, {
            // @ts-expect-error FIXME form.getHeaders() is not found
            headers: { 'Content-Type': form.getHeaders()['content-type'] },
            body: form
        })
            .expect('status', 500)
            .expect('header', 'content-type', /text\/html/)
            .expect('bodyContains', 'Error: Blocked illegal activity');
    });
    xit('POST valid image with tampered content length', () => {
        const file = node_path_1.default.resolve(__dirname, '../files/validProfileImage.jpg');
        const form = frisby.formData();
        form.append('file', node_fs_1.default.createReadStream(file)); // casting to blob as the frisby types are wrong and wont accept the fileStream type
        return frisby.post(`${REST_URL}/user/login`, {
            headers: jsonHeader,
            body: {
                email: `jim@${config_1.default.get('application.domain')}`,
                password: 'ncc-1701'
            }
        })
            .expect('status', 200)
            .then(({ json: jsonLogin }) => {
            return frisby.post(`${URL}/profile/image/file`, {
                headers: {
                    Cookie: `token=${jsonLogin.authentication.token}`,
                    // @ts-expect-error FIXME form.getHeaders() is not found
                    'Content-Type': form.getHeaders()['content-type'],
                    'Content-Length': 42
                },
                body: form,
                redirect: 'manual'
            })
                .expect('status', 500)
                .expect('bodyContains', 'Unexpected end of form');
        });
    });
});
//# sourceMappingURL=profileImageUploadSpec.js.map