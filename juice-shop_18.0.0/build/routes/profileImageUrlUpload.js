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
exports.profileImageUrlUpload = void 0;
const node_fs_1 = __importDefault(require("node:fs"));
const node_stream_1 = require("node:stream");
const promises_1 = require("node:stream/promises");
const security = __importStar(require("../lib/insecurity"));
const user_1 = require("../models/user");
const utils = __importStar(require("../lib/utils"));
const logger_1 = __importDefault(require("../lib/logger"));
function profileImageUrlUpload() {
    return async (req, res, next) => {
        if (req.body.imageUrl !== undefined) {
            const url = req.body.imageUrl;
            if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null)
                req.app.locals.abused_ssrf_bug = true;
            const loggedInUser = security.authenticatedUsers.get(req.cookies.token);
            if (loggedInUser) {
                try {
                    const response = await fetch(url);
                    if (!response.ok || !response.body) {
                        throw new Error('url returned a non-OK status code or an empty body');
                    }
                    const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg';
                    const fileStream = node_fs_1.default.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' });
                    await (0, promises_1.finished)(node_stream_1.Readable.fromWeb(response.body).pipe(fileStream));
                    await user_1.UserModel.findByPk(loggedInUser.data.id).then(async (user) => { return await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` }); }).catch((error) => { next(error); });
                }
                catch (error) {
                    try {
                        const user = await user_1.UserModel.findByPk(loggedInUser.data.id);
                        await user?.update({ profileImage: url });
                        logger_1.default.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`);
                    }
                    catch (error) {
                        next(error);
                        return;
                    }
                }
            }
            else {
                next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress));
                return;
            }
        }
        res.location(process.env.BASE_PATH + '/profile');
        res.redirect(process.env.BASE_PATH + '/profile');
    };
}
exports.profileImageUrlUpload = profileImageUrlUpload;
//# sourceMappingURL=profileImageUrlUpload.js.map