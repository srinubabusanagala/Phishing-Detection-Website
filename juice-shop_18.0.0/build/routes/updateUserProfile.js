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
exports.updateUserProfile = void 0;
const challengeUtils = __importStar(require("../lib/challengeUtils"));
const datacache_1 = require("../data/datacache");
const security = __importStar(require("../lib/insecurity"));
const user_1 = require("../models/user");
const utils = __importStar(require("../lib/utils"));
function updateUserProfile() {
    return async (req, res, next) => {
        const loggedInUser = security.authenticatedUsers.get(req.cookies.token);
        if (!loggedInUser) {
            next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress));
            return;
        }
        try {
            const user = await user_1.UserModel.findByPk(loggedInUser.data.id);
            if (!user) {
                next(new Error('User not found'));
                return;
            }
            challengeUtils.solveIf(datacache_1.challenges.csrfChallenge, () => {
                return ((req.headers.origin?.includes('://htmledit.squarefree.com')) ??
                    (req.headers.referer?.includes('://htmledit.squarefree.com'))) &&
                    req.body.username !== user.username;
            });
            const savedUser = await user.update({ username: req.body.username });
            const userWithStatus = utils.queryResultToJson(savedUser);
            const updatedToken = security.authorize(userWithStatus);
            security.authenticatedUsers.put(updatedToken, userWithStatus);
            res.cookie('token', updatedToken);
            res.location(process.env.BASE_PATH + '/profile');
            res.redirect(process.env.BASE_PATH + '/profile');
        }
        catch (error) {
            next(error);
        }
    };
}
exports.updateUserProfile = updateUserProfile;
//# sourceMappingURL=updateUserProfile.js.map