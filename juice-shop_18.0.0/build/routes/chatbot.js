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
exports.process = exports.status = exports.initializeChatbot = exports.bot = void 0;
const promises_1 = __importDefault(require("node:fs/promises"));
const user_1 = require("../models/user");
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const challengeUtils = __importStar(require("../lib/challengeUtils"));
const logger_1 = __importDefault(require("../lib/logger"));
const config_1 = __importDefault(require("config"));
const download_1 = __importDefault(require("download"));
const utils = __importStar(require("../lib/utils"));
const lodash_1 = require("lodash");
const juicy_chat_bot_1 = require("juicy-chat-bot");
const validateChatBot_1 = __importDefault(require("../lib/startup/validateChatBot"));
const security = __importStar(require("../lib/insecurity"));
const botUtils = __importStar(require("../lib/botUtils"));
const datacache_1 = require("../data/datacache");
let trainingFile = config_1.default.get('application.chatBot.trainingData');
let testCommand;
exports.bot = null;
async function initializeChatbot() {
    if (utils.isUrl(trainingFile)) {
        const file = utils.extractFilename(trainingFile);
        const data = await (0, download_1.default)(trainingFile);
        await promises_1.default.writeFile('data/chatbot/' + file, data);
    }
    await promises_1.default.copyFile('data/static/botDefaultTrainingData.json', 'data/chatbot/botDefaultTrainingData.json');
    trainingFile = utils.extractFilename(trainingFile);
    const trainingSet = await promises_1.default.readFile(`data/chatbot/${trainingFile}`, 'utf8');
    (0, validateChatBot_1.default)(JSON.parse(trainingSet));
    testCommand = JSON.parse(trainingSet).data[0].utterances[0];
    exports.bot = new juicy_chat_bot_1.Bot(config_1.default.get('application.chatBot.name'), config_1.default.get('application.chatBot.greeting'), trainingSet, config_1.default.get('application.chatBot.defaultResponse'));
    return exports.bot.train();
}
exports.initializeChatbot = initializeChatbot;
void initializeChatbot();
async function processQuery(user, req, res, next) {
    if (exports.bot == null) {
        res.status(503).send();
        return;
    }
    const username = user.username;
    if (!username) {
        res.status(200).json({
            action: 'namequery',
            body: 'I\'m sorry I didn\'t get your name. What shall I call you?'
        });
        return;
    }
    if (!exports.bot.factory.run(`currentUser('${user.id}')`)) {
        try {
            exports.bot.addUser(`${user.id}`, username);
            res.status(200).json({
                action: 'response',
                body: exports.bot.greet(`${user.id}`)
            });
        }
        catch (err) {
            next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress));
        }
        return;
    }
    if (exports.bot.factory.run(`currentUser('${user.id}')`) !== username) {
        exports.bot.addUser(`${user.id}`, username);
        try {
            exports.bot.addUser(`${user.id}`, username);
        }
        catch (err) {
            next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress));
            return;
        }
    }
    if (!req.body.query) {
        res.status(200).json({
            action: 'response',
            body: exports.bot.greet(`${user.id}`)
        });
        return;
    }
    try {
        const response = await exports.bot.respond(req.body.query, `${user.id}`);
        if (response.action === 'function') {
            // @ts-expect-error FIXME unclean usage of any type as index
            if (response.handler && botUtils[response.handler]) {
                // @ts-expect-error FIXME unclean usage of any type as index
                res.status(200).json(await botUtils[response.handler](req.body.query, user));
            }
            else {
                res.status(200).json({
                    action: 'response',
                    body: config_1.default.get('application.chatBot.defaultResponse')
                });
            }
        }
        else {
            res.status(200).json(response);
        }
    }
    catch (err) {
        try {
            await exports.bot.respond(testCommand, `${user.id}`);
            res.status(200).json({
                action: 'response',
                body: config_1.default.get('application.chatBot.defaultResponse')
            });
        }
        catch (err) {
            challengeUtils.solveIf(datacache_1.challenges.killChatbotChallenge, () => { return true; });
            res.status(200).json({
                action: 'response',
                body: `Remember to stay hydrated while I try to recover from "${utils.getErrorMessage(err)}"...`
            });
        }
    }
}
async function setUserName(user, req, res) {
    if (exports.bot == null) {
        return;
    }
    try {
        const userModel = await user_1.UserModel.findByPk(user.id);
        if (userModel == null) {
            res.status(401).json({
                status: 'error',
                error: 'Unknown user'
            });
            return;
        }
        const updatedUser = await userModel.update({ username: req.body.query });
        const updatedUserResponse = utils.queryResultToJson(updatedUser);
        const updatedToken = security.authorize(updatedUserResponse);
        security.authenticatedUsers.put(updatedToken, updatedUserResponse);
        exports.bot.addUser(`${updatedUser.id}`, req.body.query);
        res.status(200).json({
            action: 'response',
            body: exports.bot.greet(`${updatedUser.id}`),
            token: updatedToken
        });
    }
    catch (err) {
        logger_1.default.error(`Could not set username: ${utils.getErrorMessage(err)}`);
        res.status(500).send();
    }
}
const status = function status() {
    return async (req, res, next) => {
        if (exports.bot == null) {
            res.status(200).json({
                status: false,
                body: `${config_1.default.get('application.chatBot.name')} isn't ready at the moment, please wait while I set things up`
            });
            return;
        }
        const token = req.cookies.token || utils.jwtFrom(req);
        if (!token) {
            res.status(200).json({
                status: exports.bot.training.state,
                body: `Hi, I can't recognize you. Sign in to talk to ${config_1.default.get('application.chatBot.name')}`
            });
            return;
        }
        const user = await getUserFromJwt(token);
        if (user == null) {
            res.status(401).json({
                error: 'Unauthenticated user'
            });
            return;
        }
        const username = user.username;
        if (!username) {
            res.status(200).json({
                action: 'namequery',
                body: 'I\'m sorry I didn\'t get your name. What shall I call you?'
            });
            return;
        }
        try {
            exports.bot.addUser(`${user.id}`, username);
            res.status(200).json({
                status: exports.bot.training.state,
                body: exports.bot.training.state ? exports.bot.greet(`${user.id}`) : `${config_1.default.get('application.chatBot.name')} isn't ready at the moment, please wait while I set things up`
            });
        }
        catch (err) {
            next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress));
        }
    };
};
exports.status = status;
function process() {
    return async (req, res, next) => {
        if (exports.bot == null) {
            res.status(200).json({
                action: 'response',
                body: `${config_1.default.get('application.chatBot.name')} isn't ready at the moment, please wait while I set things up`
            });
        }
        const token = req.cookies.token || utils.jwtFrom(req);
        if (!token) {
            res.status(400).json({
                error: 'Unauthenticated user'
            });
            return;
        }
        const user = await getUserFromJwt(token);
        if (user == null) {
            res.status(401).json({
                error: 'Unauthenticated user'
            });
            return;
        }
        if (req.body.action === 'query') {
            await processQuery(user, req, res, next);
        }
        else if (req.body.action === 'setname') {
            await setUserName(user, req, res);
        }
    };
}
exports.process = process;
async function getUserFromJwt(token) {
    return await new Promise((resolve) => {
        jsonwebtoken_1.default.verify(token, security.publicKey, (err, decoded) => {
            if (err !== null || !decoded || (0, lodash_1.isString)(decoded)) {
                resolve(null);
            }
            else {
                resolve(decoded.data);
            }
        });
    });
}
//# sourceMappingURL=chatbot.js.map