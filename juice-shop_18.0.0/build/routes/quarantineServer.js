"use strict";
/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.serveQuarantineFiles = void 0;
const node_path_1 = __importDefault(require("node:path"));
function serveQuarantineFiles() {
    return ({ params, query }, res, next) => {
        const file = params.file;
        if (!file.includes('/')) {
            res.sendFile(node_path_1.default.resolve('ftp/quarantine/', file));
        }
        else {
            res.status(403);
            next(new Error('File names cannot contain forward slashes!'));
        }
    };
}
exports.serveQuarantineFiles = serveQuarantineFiles;
//# sourceMappingURL=quarantineServer.js.map