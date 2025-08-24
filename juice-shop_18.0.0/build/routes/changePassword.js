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
exports.changePassword = void 0;
const challengeUtils = __importStar(require("../lib/challengeUtils"));
const datacache_1 = require("../data/datacache");
const user_1 = require("../models/user");
const security = __importStar(require("../lib/insecurity"));
function changePassword() {
    return async ({ query, headers, connection }, res, next) => {
        const currentPassword = query.current;
        const newPassword = query.new;
        const newPasswordInString = newPassword?.toString();
        const repeatPassword = query.repeat;
        if (!newPassword || newPassword === 'undefined') {
            res.status(401).send(res.__('Password cannot be empty.'));
            return;
        }
        else if (newPassword !== repeatPassword) {
            res.status(401).send(res.__('New and repeated password do not match.'));
            return;
        }
        const token = headers.authorization ? headers.authorization.substr('Bearer='.length) : null;
        if (token === null) {
            next(new Error('Blocked illegal activity by ' + connection.remoteAddress));
            return;
        }
        const loggedInUser = security.authenticatedUsers.get(token);
        if (!loggedInUser) {
            next(new Error('Blocked illegal activity by ' + connection.remoteAddress));
            return;
        }
        if (currentPassword && security.hash(currentPassword) !== loggedInUser.data.password) {
            res.status(401).send(res.__('Current password is not correct.'));
            return;
        }
        try {
            const user = await user_1.UserModel.findByPk(loggedInUser.data.id);
            if (!user) {
                res.status(404).send(res.__('User not found.'));
                return;
            }
            await user.update({ password: newPasswordInString });
            challengeUtils.solveIf(datacache_1.challenges.changePasswordBenderChallenge, () => user.id === 3 && !currentPassword && user.password === security.hash('slurmCl4ssic'));
            res.json({ user });
        }
        catch (error) {
            next(error);
        }
    };
}
exports.changePassword = changePassword;
//# sourceMappingURL=changePassword.js.map