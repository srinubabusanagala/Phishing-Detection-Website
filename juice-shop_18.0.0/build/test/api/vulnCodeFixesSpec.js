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
const frisby_1 = require("frisby");
const URL = 'http://localhost:3000';
describe('/snippets/fixes/:key', () => {
    it('GET fixes for unknown challenge key throws error', () => {
        return frisby.get(URL + '/snippets/fixes/doesNotExistChallenge')
            .expect('status', 404)
            .expect('json', 'error', 'No fixes found for the snippet!');
    });
    it('GET fixes for existing challenge key', () => {
        return frisby.get(URL + '/snippets/fixes/resetPasswordBenderChallenge')
            .expect('status', 200)
            .expect('jsonTypes', {
            fixes: frisby_1.Joi.array().items(frisby_1.Joi.string())
        })
            .expect('jsonTypes', {
            fixes: frisby_1.Joi.array().length(3)
        });
    });
});
describe('/snippets/fixes', () => {
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
    it('POST fix for non-existing challenge key throws error', () => {
        return frisby.post(URL + '/snippets/fixes', {
            body: {
                key: 'doesNotExistChallenge',
                selectedFix: 1
            }
        })
            .expect('status', 404)
            .expect('json', 'error', 'No fixes found for the snippet!');
    });
    it('POST wrong fix for existing challenge key gives negative verdict and explanation', () => {
        return frisby.post(URL + '/snippets/fixes', {
            body: {
                key: 'resetPasswordBenderChallenge',
                selectedFix: 0
            }
        })
            .expect('status', 200)
            .expect('json', {
            verdict: false,
            explanation: 'While not necessarily as trivial to research via a user\'s LinkedIn profile, the question is still easy to research or brute force when answered truthfully.'
        });
    });
    it('POST non-existing fix for existing challenge key gives negative verdict and no explanation', () => {
        return frisby.post(URL + '/snippets/fixes', {
            body: {
                key: 'resetPasswordBenderChallenge',
                selectedFix: 42
            }
        })
            .expect('status', 200)
            .expect('json', {
            verdict: false
        });
    });
    it('POST correct fix for existing challenge key gives positive verdict and explanation', async () => {
        const websocketReceivedPromise = new Promise((resolve) => {
            socket.once('code challenge solved', (data) => {
                (0, globals_1.expect)(data).toEqual({
                    key: 'resetPasswordBenderChallenge',
                    codingChallengeStatus: 2
                });
                resolve();
            });
        });
        await frisby.post(URL + '/snippets/fixes', {
            body: {
                key: 'resetPasswordBenderChallenge',
                selectedFix: 1
            }
        })
            .expect('status', 200)
            .expect('json', {
            verdict: true,
            explanation: 'When answered truthfully, all security questions are susceptible to online research (on Facebook, LinkedIn etc.) and often even brute force. If at all, they should not be used as the only factor for a security-relevant function.'
        })
            .promise();
        await websocketReceivedPromise;
    });
});
//# sourceMappingURL=vulnCodeFixesSpec.js.map