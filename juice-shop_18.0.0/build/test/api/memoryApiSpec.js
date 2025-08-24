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
const globals_1 = require("@jest/globals");
const config_1 = __importDefault(require("config"));
const node_path_1 = __importDefault(require("node:path"));
const node_fs_1 = __importDefault(require("node:fs"));
const jsonHeader = { 'content-type': 'application/json' };
const REST_URL = 'http://localhost:3000/rest';
describe('/rest/memories', () => {
    it('GET memories via public API', () => {
        return frisby.get(REST_URL + '/memories')
            .expect('status', 200);
    });
    it('GET memories via a valid authorization token', () => {
        return frisby.post(REST_URL + '/user/login', {
            headers: jsonHeader,
            body: {
                email: 'jim@' + config_1.default.get('application.domain'),
                password: 'ncc-1701'
            }
        })
            .expect('status', 200)
            .then(({ json: jsonLogin }) => {
            return frisby.get(REST_URL + '/memories', {
                headers: { Authorization: 'Bearer ' + jsonLogin.authentication.token, 'content-type': 'application/json' }
            })
                .expect('status', 200);
        });
    });
    it('POST new memory is forbidden via public API', () => {
        const file = node_path_1.default.resolve(__dirname, '../files/validProfileImage.jpg');
        const form = frisby.formData();
        form.append('image', node_fs_1.default.createReadStream(file), 'Valid Image'); // casting to blob as the frisby types are wrong and wont accept the fileStream type 'Valid Image')
        form.append('caption', 'Valid Image');
        return frisby.post(REST_URL + '/memories', {
            headers: {
                // @ts-expect-error FIXME form.getHeaders() is not found
                'Content-Type': form.getHeaders()['content-type']
            },
            body: form
        })
            .expect('status', 401);
    });
    it('POST new memory image file invalid type', () => {
        const file = node_path_1.default.resolve(__dirname, '../files/invalidProfileImageType.docx');
        const form = frisby.formData();
        form.append('image', node_fs_1.default.createReadStream(file), 'Valid Image'); // casting to blob as the frisby types are wrong and wont accept the fileStream type 'Valid Image')
        form.append('caption', 'Valid Image');
        return frisby.post(REST_URL + '/user/login', {
            headers: jsonHeader,
            body: {
                email: 'jim@' + config_1.default.get('application.domain'),
                password: 'ncc-1701'
            }
        })
            .expect('status', 200)
            .then(({ json: jsonLogin }) => {
            return frisby.post(REST_URL + '/memories', {
                headers: {
                    Authorization: 'Bearer ' + jsonLogin.authentication.token,
                    // @ts-expect-error FIXME form.getHeaders() is not found
                    'Content-Type': form.getHeaders()['content-type']
                },
                body: form
            })
                .expect('status', 500);
        });
    });
    it('POST new memory image file is not passed - 1', () => {
        return frisby.post(REST_URL + '/user/login', {
            headers: jsonHeader,
            body: {
                email: 'jim@' + config_1.default.get('application.domain'),
                password: 'ncc-1701'
            }
        })
            .expect('status', 200)
            .then(({ json: jsonLogin }) => {
            return frisby.post(REST_URL + '/memories', {
                headers: {
                    Authorization: 'Bearer ' + jsonLogin.authentication.token
                }
            })
                .expect('status', 400)
                .expect('json', {
                error: 'File is not passed'
            });
        });
    });
    it('POST new memory image file is not passed - 2', () => {
        const form = frisby.formData();
        form.append('key1', 'value1');
        form.append('key2', 'value2');
        return frisby.post(REST_URL + '/user/login', {
            headers: jsonHeader,
            body: {
                email: 'jim@' + config_1.default.get('application.domain'),
                password: 'ncc-1701'
            }
        })
            .expect('status', 200)
            .then(({ json: jsonLogin }) => {
            return frisby.post(REST_URL + '/memories', {
                headers: {
                    Authorization: 'Bearer ' + jsonLogin.authentication.token,
                    // @ts-expect-error FIXME form.getHeaders() is not found
                    'Content-Type': form.getHeaders()['content-type']
                },
                body: form
            })
                .expect('status', 400)
                .expect('json', {
                error: 'File is not passed'
            });
        });
    });
    it('POST new memory with valid for JPG format image', () => {
        const file = node_path_1.default.resolve(__dirname, '../files/validProfileImage.jpg');
        const form = frisby.formData();
        form.append('image', node_fs_1.default.createReadStream(file), 'Valid Image'); // casting to blob as the frisby types are wrong and wont accept the fileStream type 'Valid Image')
        form.append('caption', 'Valid Image');
        return frisby.post(REST_URL + '/user/login', {
            headers: jsonHeader,
            body: {
                email: 'jim@' + config_1.default.get('application.domain'),
                password: 'ncc-1701'
            }
        })
            .expect('status', 200)
            .then(({ json: jsonLogin }) => {
            return frisby.post(REST_URL + '/memories', {
                headers: {
                    Authorization: 'Bearer ' + jsonLogin.authentication.token,
                    // @ts-expect-error FIXME form.getHeaders() is not found
                    'Content-Type': form.getHeaders()['content-type']
                },
                body: form
            })
                .expect('status', 200)
                .then(({ json }) => {
                (0, globals_1.expect)(json.data.caption).toBe('Valid Image');
                (0, globals_1.expect)(json.data.UserId).toBe(2);
            });
        });
    });
    it('Should not crash the node-js server when sending invalid content like described in CVE-2022-24434', () => {
        return frisby.post(REST_URL + '/memories', {
            headers: {
                'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundaryoo6vortfDzBsDiro',
                'Content-Length': '145'
            },
            body: '------WebKitFormBoundaryoo6vortfDzBsDiro\r\n Content-Disposition: form-data; name="bildbeschreibung"\r\n\r\n\r\n------WebKitFormBoundaryoo6vortfDzBsDiro--'
        })
            .expect('status', 500)
            .expect('bodyContains', 'Error: Malformed part header');
    });
});
//# sourceMappingURL=memoryApiSpec.js.map