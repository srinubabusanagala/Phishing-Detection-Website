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
exports.retrieveLoggedInUser = void 0;
const challengeUtils = __importStar(require("../lib/challengeUtils"));
const datacache_1 = require("../data/datacache");
const security = __importStar(require("../lib/insecurity"));
function retrieveLoggedInUser() {
    return (req, res) => {
        let user;
        try {
            if (security.verify(req.cookies.token)) {
                user = security.authenticatedUsers.get(req.cookies.token);
            }
        }
        catch (err) {
            user = undefined;
        }
        finally {
            const response = { user: { id: (user?.data ? user.data.id : undefined), email: (user?.data ? user.data.email : undefined), lastLoginIp: (user?.data ? user.data.lastLoginIp : undefined), profileImage: (user?.data ? user.data.profileImage : undefined) } };
            if (req.query.callback === undefined) {
                res.json(response);
            }
            else {
                challengeUtils.solveIf(datacache_1.challenges.emailLeakChallenge, () => { return true; });
                res.jsonp(response);
            }
        }
    };
}
exports.retrieveLoggedInUser = retrieveLoggedInUser;
//# sourceMappingURL=currentUser.js.map