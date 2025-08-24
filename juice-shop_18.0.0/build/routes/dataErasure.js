"use strict";
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
/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
const express_1 = __importDefault(require("express"));
const node_path_1 = __importDefault(require("node:path"));
const securityQuestion_1 = require("../models/securityQuestion");
const privacyRequests_1 = require("../models/privacyRequests");
const securityAnswer_1 = require("../models/securityAnswer");
const challengeUtils = __importStar(require("../lib/challengeUtils"));
const datacache_1 = require("../data/datacache");
const security = __importStar(require("../lib/insecurity"));
const user_1 = require("../models/user");
const router = express_1.default.Router();
router.get('/', async (req, res, next) => {
    const loggedInUser = security.authenticatedUsers.get(req.cookies.token);
    if (!loggedInUser) {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress));
        return;
    }
    const email = loggedInUser.data.email;
    try {
        const answer = await securityAnswer_1.SecurityAnswerModel.findOne({
            include: [{
                    model: user_1.UserModel,
                    where: { email }
                }]
        });
        if (answer == null) {
            throw new Error('No answer found!');
        }
        const question = await securityQuestion_1.SecurityQuestionModel.findByPk(answer.SecurityQuestionId);
        if (question == null) {
            throw new Error('No question found!');
        }
        res.render('dataErasureForm', { userEmail: email, securityQuestion: question.question });
    }
    catch (error) {
        next(error);
    }
});
// eslint-disable-next-line @typescript-eslint/no-misused-promises
router.post('/', async (req, res, next) => {
    const loggedInUser = security.authenticatedUsers.get(req.cookies.token);
    if (!loggedInUser) {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress));
        return;
    }
    try {
        await privacyRequests_1.PrivacyRequestModel.create({
            UserId: loggedInUser.data.id,
            deletionRequested: true
        });
        res.clearCookie('token');
        if (req.body.layout) {
            const filePath = node_path_1.default.resolve(req.body.layout).toLowerCase();
            const isForbiddenFile = (filePath.includes('ftp') || filePath.includes('ctf.key') || filePath.includes('encryptionkeys'));
            if (!isForbiddenFile) {
                res.render('dataErasureResult', {
                    ...req.body
                }, (error, html) => {
                    if (!html || error) {
                        next(new Error(error.message));
                    }
                    else {
                        const sendlfrResponse = html.slice(0, 100) + '......';
                        res.send(sendlfrResponse);
                        challengeUtils.solveIf(datacache_1.challenges.lfrChallenge, () => { return true; });
                    }
                });
            }
            else {
                next(new Error('File access not allowed'));
            }
        }
        else {
            res.render('dataErasureResult', {
                ...req.body
            });
        }
    }
    catch (error) {
        next(error);
    }
});
exports.default = router;
//# sourceMappingURL=dataErasure.js.map