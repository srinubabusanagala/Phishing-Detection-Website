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
const chatbot_1 = require("../../routes/chatbot");
const promises_1 = __importDefault(require("node:fs/promises"));
const utils = __importStar(require("../../lib/utils"));
const URL = 'http://localhost:3000';
const REST_URL = `${URL}/rest/`;
const API_URL = `${URL}/api/`;
let trainingData;
async function login({ email, password }) {
    // @ts-expect-error FIXME promise return handling broken
    const loginRes = await frisby
        .post(REST_URL + '/user/login', {
        email,
        password
    }).catch((res) => {
        if (res.json?.type && res.json.status === 'totp_token_required') {
            return res;
        }
        throw new Error(`Failed to login '${email}'`);
    });
    return loginRes.json.authentication;
}
describe('/chatbot', () => {
    beforeAll(async () => {
        await (0, chatbot_1.initializeChatbot)();
        trainingData = JSON.parse(await promises_1.default.readFile(`data/chatbot/${utils.extractFilename(config_1.default.get('application.chatBot.trainingData'))}`, { encoding: 'utf8' }));
    });
    describe('/status', () => {
        it('GET bot training state', () => {
            return frisby.get(REST_URL + 'chatbot/status')
                .expect('status', 200)
                .expect('json', 'status', true);
        });
        it('GET bot state for anonymous users contains log in request', () => {
            return frisby.get(REST_URL + 'chatbot/status')
                .expect('status', 200)
                .expect('json', 'body', /Sign in to talk/);
        });
        it('GET bot state for authenticated users contains request for username', async () => {
            const { token } = await login({
                email: `J12934@${config_1.default.get('application.domain')}`,
                password: '0Y8rMnww$*9VFYE§59-!Fg1L6t&6lB'
            });
            await frisby.setup({
                request: {
                    headers: {
                        Authorization: `Bearer ${token}`,
                        'Content-Type': 'application/json'
                    }
                }
            }, true).get(REST_URL + 'chatbot/status')
                .expect('status', 200)
                .expect('json', 'body', /What shall I call you?/)
                .promise();
        });
    });
    describe('/respond', () => {
        it('Asks for username if not defined', async () => {
            const { token } = await login({
                email: `J12934@${config_1.default.get('application.domain')}`,
                password: '0Y8rMnww$*9VFYE§59-!Fg1L6t&6lB'
            });
            const testCommand = trainingData.data[0].utterances[0];
            await frisby.setup({
                request: {
                    headers: {
                        Authorization: `Bearer ${token}`,
                        'Content-Type': 'application/json'
                    }
                }
            }, true)
                .post(REST_URL + 'chatbot/respond', {
                body: {
                    action: 'query',
                    query: testCommand
                }
            })
                .expect('status', 200)
                .expect('json', 'action', 'namequery')
                .expect('json', 'body', 'I\'m sorry I didn\'t get your name. What shall I call you?')
                .promise();
        });
        it('Returns greeting if username is defined', async () => {
            if (chatbot_1.bot == null) {
                throw new Error('Bot not initializeChatbotd');
            }
            const { token } = await login({
                email: 'bjoern.kimminich@gmail.com',
                password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='
            });
            chatbot_1.bot.addUser('1337', 'bkimminich');
            const testCommand = trainingData.data[0].utterances[0];
            await frisby.setup({
                request: {
                    headers: {
                        Authorization: `Bearer ${token}`,
                        'Content-Type': 'application/json'
                    }
                }
            }, true)
                .post(REST_URL + 'chatbot/respond', {
                body: {
                    action: 'query',
                    query: testCommand
                }
            })
                .expect('status', 200)
                .expect('json', 'action', 'response')
                .expect('json', 'body', chatbot_1.bot.greet('1337'))
                .promise();
        });
        it('Returns proper response for registered user', async () => {
            if (chatbot_1.bot == null) {
                throw new Error('Bot not initializeChatbotd');
            }
            const { token } = await login({
                email: 'bjoern.kimminich@gmail.com',
                password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='
            });
            chatbot_1.bot.addUser('12345', 'bkimminich');
            const testCommand = trainingData.data[0].utterances[0];
            await frisby.setup({
                request: {
                    headers: {
                        Authorization: `Bearer ${token}`,
                        'Content-Type': 'application/json'
                    }
                }
            }, true)
                .post(REST_URL + 'chatbot/respond', {
                body: {
                    action: 'query',
                    query: testCommand
                }
            })
                .post(REST_URL + 'chatbot/respond', {
                body: {
                    action: 'query',
                    query: testCommand
                }
            })
                .expect('status', 200)
                .promise()
                .then(({ json }) => {
                (0, globals_1.expect)(trainingData.data[0].answers).toContainEqual(json);
            });
        });
        it('Responds with product price when asked question with product name', async () => {
            const { token } = await login({
                email: 'bjoern.kimminich@gmail.com',
                password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='
            });
            const { json } = await frisby.get(API_URL + '/Products/1')
                .expect('status', 200)
                .promise();
            await frisby.setup({
                request: {
                    headers: {
                        Authorization: `Bearer ${token}`,
                        'Content-Type': 'application/json'
                    }
                }
            }, true)
                .post(REST_URL + 'chatbot/respond', {
                body: {
                    action: 'query',
                    query: 'How much is ' + json.data.name + '?'
                }
            })
                .expect('status', 200)
                .expect('json', 'action', 'response')
                .promise()
                .then(({ body = json.body }) => {
                (0, globals_1.expect)(body).toContain(`${json.data.name} costs ${json.data.price}¤`);
            });
        });
        it('Greets back registered user after being told username', async () => {
            const { token } = await login({
                email: `stan@${config_1.default.get('application.domain')}`,
                password: 'ship coffin krypt cross estate supply insurance asbestos souvenir'
            });
            await frisby.setup({
                request: {
                    headers: {
                        Authorization: `Bearer ${token}`,
                        'Content-Type': 'application/json'
                    }
                }
            }, true)
                .post(REST_URL + 'chatbot/respond', {
                body: {
                    action: 'setname',
                    query: 'NotGuybrushThreepwood'
                }
            })
                .expect('status', 200)
                .expect('json', 'action', 'response')
                .expect('json', 'body', /NotGuybrushThreepwood/)
                .promise();
        });
        it('POST returns error for unauthenticated user', () => {
            const testCommand = trainingData.data[0].utterances[0];
            return frisby.setup({
                request: {
                    headers: {
                        Authorization: 'Bearer faketoken',
                        'Content-Type': 'application/json'
                    }
                }
            }, true)
                .post(REST_URL + 'chatbot/respond', {
                body: {
                    query: testCommand
                }
            })
                .expect('status', 401)
                .expect('json', 'error', 'Unauthenticated user');
        });
        it('Returns proper response for custom callbacks', async () => {
            const functionTest = trainingData.data.filter(data => data.intent === 'queries.functionTest');
            const { token } = await login({
                email: 'bjoern.kimminich@gmail.com',
                password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='
            });
            const testCommand = functionTest[0].utterances[0];
            const testResponse = '3be2e438b7f3d04c89d7749f727bb3bd';
            await frisby.setup({
                request: {
                    headers: {
                        Authorization: `Bearer ${token}`,
                        'Content-Type': 'application/json'
                    }
                }
            }, true)
                .post(REST_URL + 'chatbot/respond', {
                body: {
                    action: 'query',
                    query: testCommand
                }
            })
                .post(REST_URL + 'chatbot/respond', {
                body: {
                    action: 'query',
                    query: testCommand
                }
            })
                .expect('status', 200)
                .expect('json', 'action', 'response')
                .expect('json', 'body', testResponse)
                .promise();
        });
        it('Returns a 500 when the user name is set to crash request', async () => {
            await frisby.post(`${API_URL}/Users`, {
                headers: {
                    'Content-Type': 'application/json'
                },
                body: {
                    email: `chatbot-testuser@${config_1.default.get('application.domain')}`,
                    password: 'testtesttest',
                    username: '"',
                    role: 'admin'
                }
            }).promise();
            const { token } = await login({
                email: `chatbot-testuser@${config_1.default.get('application.domain')}`,
                password: 'testtesttest'
            });
            const functionTest = trainingData.data.filter(data => data.intent === 'queries.functionTest');
            const testCommand = functionTest[0].utterances[0];
            await frisby.post(REST_URL + 'chatbot/respond', {
                headers: {
                    Authorization: `Bearer ${token}`,
                    'Content-Type': 'application/json'
                },
                body: {
                    action: 'query',
                    query: testCommand
                }
            })
                .inspectResponse()
                .expect('status', 500)
                .promise();
        });
    });
});
//# sourceMappingURL=chatBotSpec.js.map