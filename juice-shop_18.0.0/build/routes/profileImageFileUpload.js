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
exports.profileImageFileUpload = void 0;
const promises_1 = __importDefault(require("node:fs/promises"));
const file_type_1 = __importDefault(require("file-type"));
const logger_1 = __importDefault(require("../lib/logger"));
const utils = __importStar(require("../lib/utils"));
const user_1 = require("../models/user");
const security = __importStar(require("../lib/insecurity"));
function profileImageFileUpload() {
    return async (req, res, next) => {
        const file = req.file;
        const buffer = file?.buffer;
        if (buffer === undefined) {
            res.status(500);
            next(new Error('Illegal file type'));
            return;
        }
        const uploadedFileType = await file_type_1.default.fromBuffer(buffer);
        if (uploadedFileType === undefined) {
            res.status(500);
            next(new Error('Illegal file type'));
            return;
        }
        if (uploadedFileType === null || !utils.startsWith(uploadedFileType.mime, 'image')) {
            res.status(415);
            next(new Error(`Profile image upload does not accept this file type${uploadedFileType ? (': ' + uploadedFileType.mime) : '.'}`));
            return;
        }
        const loggedInUser = security.authenticatedUsers.get(req.cookies.token);
        if (!loggedInUser) {
            next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress));
            return;
        }
        const filePath = `frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${uploadedFileType.ext}`;
        try {
            await promises_1.default.writeFile(filePath, buffer);
        }
        catch (err) {
            logger_1.default.warn('Error writing file: ' + (err instanceof Error ? err.message : String(err)));
        }
        try {
            const user = await user_1.UserModel.findByPk(loggedInUser.data.id);
            if (user != null) {
                await user.update({ profileImage: `assets/public/images/uploads/${loggedInUser.data.id}.${uploadedFileType.ext}` });
            }
        }
        catch (error) {
            next(error);
        }
        res.location(process.env.BASE_PATH + '/profile');
        res.redirect(process.env.BASE_PATH + '/profile');
    };
}
exports.profileImageFileUpload = profileImageFileUpload;
//# sourceMappingURL=profileImageFileUpload.js.map