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
exports.getUserProfile = void 0;
const html_entities_1 = require("html-entities");
const config_1 = __importDefault(require("config"));
const pug_1 = __importDefault(require("pug"));
const promises_1 = __importDefault(require("node:fs/promises"));
const challengeUtils = __importStar(require("../lib/challengeUtils"));
const themes_1 = require("../views/themes/themes");
const datacache_1 = require("../data/datacache");
const security = __importStar(require("../lib/insecurity"));
const user_1 = require("../models/user");
const utils = __importStar(require("../lib/utils"));
const entities = new html_entities_1.AllHtmlEntities();
function favicon() {
    return utils.extractFilename(config_1.default.get('application.favicon'));
}
function getUserProfile() {
    return async (req, res, next) => {
        let template;
        try {
            template = await promises_1.default.readFile('views/userProfile.pug', { encoding: 'utf-8' });
        }
        catch (err) {
            next(err);
            return;
        }
        const loggedInUser = security.authenticatedUsers.get(req.cookies.token);
        if (!loggedInUser) {
            next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress));
            return;
        }
        let user;
        try {
            user = await user_1.UserModel.findByPk(loggedInUser.data.id);
        }
        catch (error) {
            next(error);
            return;
        }
        if (!user) {
            next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress));
            return;
        }
        let username = user.username;
        if (username?.match(/#{(.*)}/) !== null && utils.isChallengeEnabled(datacache_1.challenges.usernameXssChallenge)) {
            req.app.locals.abused_ssti_bug = true;
            const code = username?.substring(2, username.length - 1);
            try {
                if (!code) {
                    throw new Error('Username is null');
                }
                username = eval(code); // eslint-disable-line no-eval
            }
            catch (err) {
                username = '\\' + username;
            }
        }
        else {
            username = '\\' + username;
        }
        const themeKey = config_1.default.get('application.theme');
        const theme = themes_1.themes[themeKey] || themes_1.themes['bluegrey-lightgreen'];
        if (username) {
            template = template.replace(/_username_/g, username);
        }
        template = template.replace(/_emailHash_/g, security.hash(user?.email));
        template = template.replace(/_title_/g, entities.encode(config_1.default.get('application.name')));
        template = template.replace(/_favicon_/g, favicon());
        template = template.replace(/_bgColor_/g, theme.bgColor);
        template = template.replace(/_textColor_/g, theme.textColor);
        template = template.replace(/_navColor_/g, theme.navColor);
        template = template.replace(/_primLight_/g, theme.primLight);
        template = template.replace(/_primDark_/g, theme.primDark);
        template = template.replace(/_logo_/g, utils.extractFilename(config_1.default.get('application.logo')));
        const fn = pug_1.default.compile(template);
        const CSP = `img-src 'self' ${user?.profileImage}; script-src 'self' 'unsafe-eval' https://code.getmdl.io http://ajax.googleapis.com`;
        challengeUtils.solveIf(datacache_1.challenges.usernameXssChallenge, () => {
            return username && user?.profileImage.match(/;[ ]*script-src(.)*'unsafe-inline'/g) !== null && utils.contains(username, '<script>alert(`xss`)</script>');
        });
        res.set({
            'Content-Security-Policy': CSP
        });
        res.send(fn(user));
    };
}
exports.getUserProfile = getUserProfile;
//# sourceMappingURL=userProfile.js.map