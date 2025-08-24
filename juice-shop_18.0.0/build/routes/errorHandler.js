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
exports.errorHandler = void 0;
const promises_1 = __importDefault(require("node:fs/promises"));
const config_1 = __importDefault(require("config"));
const pug_1 = __importDefault(require("pug"));
const utils = __importStar(require("../lib/utils"));
function errorHandler() {
    return async (error, req, res, next) => {
        if (res.headersSent) {
            next(error);
            return;
        }
        if (req?.headers?.accept === 'application/json') {
            res.status(500).json({ error: JSON.parse(JSON.stringify(error)) });
            return;
        }
        const template = await promises_1.default.readFile('views/errorPage.pug', { encoding: 'utf-8' });
        const title = `${config_1.default.get('application.name')} (Express ${utils.version('express')})`;
        const fn = pug_1.default.compile(template);
        res.status(500).send(fn({ title, error }));
    };
}
exports.errorHandler = errorHandler;
//# sourceMappingURL=errorHandler.js.map