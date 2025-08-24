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
const node_path_1 = __importDefault(require("node:path"));
const utils = __importStar(require("../utils"));
const logger_1 = __importDefault(require("../logger"));
const promises_1 = require("node:fs/promises");
const glob_1 = require("glob");
const exists = async (path) => await (0, promises_1.access)(path).then(() => true).catch(() => false);
const restoreOverwrittenFilesWithOriginals = async () => {
    await (0, promises_1.copyFile)(node_path_1.default.resolve('data/static/legal.md'), node_path_1.default.resolve('ftp/legal.md'));
    if (await exists(node_path_1.default.resolve('frontend/dist'))) {
        await (0, promises_1.copyFile)(node_path_1.default.resolve('data/static/owasp_promo.vtt'), node_path_1.default.resolve('frontend/dist/frontend/assets/public/videos/owasp_promo.vtt'));
    }
    try {
        const files = await (0, glob_1.glob)(node_path_1.default.resolve('data/static/i18n/*.json'));
        await Promise.all(files.map(async (filename) => {
            await (0, promises_1.copyFile)(filename, node_path_1.default.resolve('i18n/', filename.substring(filename.lastIndexOf('/') + 1)));
        }));
    }
    catch (err) {
        logger_1.default.warn('Error listing JSON files in /data/static/i18n folder: ' + utils.getErrorMessage(err));
    }
};
exports.default = restoreOverwrittenFilesWithOriginals;
//# sourceMappingURL=restoreOverwrittenFilesWithOriginals.js.map