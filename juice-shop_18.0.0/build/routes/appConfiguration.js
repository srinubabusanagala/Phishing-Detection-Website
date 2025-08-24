"use strict";
/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.retrieveAppConfiguration = void 0;
const config_1 = __importDefault(require("config"));
function retrieveAppConfiguration() {
    return (_req, res) => {
        res.json({ config: config_1.default });
    };
}
exports.retrieveAppConfiguration = retrieveAppConfiguration;
//# sourceMappingURL=appConfiguration.js.map