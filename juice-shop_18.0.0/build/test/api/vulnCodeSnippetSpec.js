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
const globals_1 = require("@jest/globals");
const frisby = __importStar(require("frisby"));
const socket_io_client_1 = __importDefault(require("socket.io-client"));
const Joi = frisby.Joi;
const URL = 'http://localhost:3000';
describe('/snippets/:challenge', () => {
    it('GET code snippet retrieval for unknown challenge key throws error', () => {
        return frisby.get(URL + '/snippets/doesNotExistChallenge')
            .expect('status', 404)
            .expect('json', 'error', 'No code challenge for challenge key: doesNotExistChallenge');
    });
    it('GET code snippet retrieval for challenge without code snippet throws error', () => {
        return frisby.get(URL + '/snippets/easterEggLevelTwoChallenge')
            .expect('status', 404)
            .expect('json', 'error', 'No code challenge for challenge key: easterEggLevelTwoChallenge');
    });
    it('GET code snippet retrieval for challenge with code snippet', () => {
        return frisby.get(URL + '/snippets/loginAdminChallenge')
            .expect('status', 200)
            .expect('jsonTypes', {
            snippet: Joi.string(),
            vulnLines: Joi.array()
        });
    });
});
describe('snippets/verdict', () => {
    let socket;
    beforeEach(done => {
        socket = (0, socket_io_client_1.default)('http://localhost:3000', {
            reconnectionDelay: 0,
            forceNew: true
        });
        socket.on('connect', () => {
            done();
        });
    });
    afterEach(done => {
        if (socket.connected) {
            socket.disconnect();
        }
        done();
    });
    it('should check for the incorrect lines', () => {
        return frisby.post(URL + '/snippets/verdict', {
            body: {
                selectedLines: [5, 9],
                key: 'resetPasswordJimChallenge'
            }
        })
            .expect('status', 200)
            .expect('jsonTypes', {
            verdict: Joi.boolean()
        })
            .expect('json', {
            verdict: false
        });
    });
    it('should check for the correct lines', async () => {
        const websocketReceivedPromise = new Promise((resolve) => {
            socket.once('code challenge solved', (data) => {
                (0, globals_1.expect)(data).toEqual({
                    key: 'resetPasswordJimChallenge',
                    codingChallengeStatus: 1
                });
                resolve();
            });
        });
        await frisby.post(URL + '/snippets/verdict', {
            body: {
                selectedLines: [2],
                key: 'resetPasswordJimChallenge'
            }
        })
            .expect('status', 200)
            .expect('jsonTypes', {
            verdict: Joi.boolean()
        })
            .expect('json', {
            verdict: true
        })
            .promise();
        await websocketReceivedPromise;
    });
});
//# sourceMappingURL=vulnCodeSnippetSpec.js.map