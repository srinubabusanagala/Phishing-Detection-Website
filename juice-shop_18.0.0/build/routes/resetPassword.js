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
exports.resetPassword = void 0;
const config_1 = __importDefault(require("config"));
const securityAnswer_1 = require("../models/securityAnswer");
const challengeUtils = __importStar(require("../lib/challengeUtils"));
const datacache_1 = require("../data/datacache");
const security = __importStar(require("../lib/insecurity"));
const user_1 = require("../models/user");
function resetPassword() {
    return ({ body, connection }, res, next) => {
        const email = body.email;
        const answer = body.answer;
        const newPassword = body.new;
        const repeatPassword = body.repeat;
        if (!email || !answer) {
            next(new Error('Blocked illegal activity by ' + connection.remoteAddress));
        }
        else if (!newPassword || newPassword === 'undefined') {
            res.status(401).send(res.__('Password cannot be empty.'));
        }
        else if (newPassword !== repeatPassword) {
            res.status(401).send(res.__('New and repeated password do not match.'));
        }
        else {
            securityAnswer_1.SecurityAnswerModel.findOne({
                include: [{
                        model: user_1.UserModel,
                        where: { email }
                    }]
            }).then((data) => {
                if ((data != null) && security.hmac(answer) === data.answer) {
                    user_1.UserModel.findByPk(data.UserId).then((user) => {
                        user?.update({ password: newPassword }).then((user) => {
                            verifySecurityAnswerChallenges(user, answer);
                            res.json({ user });
                        }).catch((error) => {
                            next(error);
                        });
                    }).catch((error) => {
                        next(error);
                    });
                }
                else {
                    res.status(401).send(res.__('Wrong answer to security question.'));
                }
            }).catch((error) => {
                next(error);
            });
        }
    };
}
exports.resetPassword = resetPassword;
function verifySecurityAnswerChallenges(user, answer) {
    challengeUtils.solveIf(datacache_1.challenges.resetPasswordJimChallenge, () => { return user.id === datacache_1.users.jim.id && answer === 'Samuel'; });
    challengeUtils.solveIf(datacache_1.challenges.resetPasswordBenderChallenge, () => { return user.id === datacache_1.users.bender.id && answer === 'Stop\'n\'Drop'; });
    challengeUtils.solveIf(datacache_1.challenges.resetPasswordBjoernChallenge, () => { return user.id === datacache_1.users.bjoern.id && answer === 'West-2082'; });
    challengeUtils.solveIf(datacache_1.challenges.resetPasswordMortyChallenge, () => { return user.id === datacache_1.users.morty.id && answer === '5N0wb41L'; });
    challengeUtils.solveIf(datacache_1.challenges.resetPasswordBjoernOwaspChallenge, () => { return user.id === datacache_1.users.bjoernOwasp.id && answer === 'Zaya'; });
    challengeUtils.solveIf(datacache_1.challenges.resetPasswordUvoginChallenge, () => { return user.id === datacache_1.users.uvogin.id && answer === 'Silence of the Lambs'; });
    challengeUtils.solveIf(datacache_1.challenges.geoStalkingMetaChallenge, () => {
        const securityAnswer = ((() => {
            const memories = config_1.default.get('memories');
            for (let i = 0; i < memories.length; i++) {
                if (memories[i].geoStalkingMetaSecurityAnswer) {
                    return memories[i].geoStalkingMetaSecurityAnswer;
                }
            }
        })());
        return user.id === datacache_1.users.john.id && answer === securityAnswer;
    });
    challengeUtils.solveIf(datacache_1.challenges.geoStalkingVisualChallenge, () => {
        const securityAnswer = ((() => {
            const memories = config_1.default.get('memories');
            for (let i = 0; i < memories.length; i++) {
                if (memories[i].geoStalkingVisualSecurityAnswer) {
                    return memories[i].geoStalkingVisualSecurityAnswer;
                }
            }
        })());
        return user.id === datacache_1.users.emma.id && answer === securityAnswer;
    });
}
//# sourceMappingURL=resetPassword.js.map