"use strict";
/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.countryMapping = void 0;
const logger_1 = __importDefault(require("../lib/logger"));
const config_1 = __importDefault(require("config"));
function countryMapping(config = config_1.default) {
    return (req, res) => {
        try {
            const countryMapping = config.get('ctf.countryMapping');
            if (!countryMapping) {
                throw new Error('No country mapping found!');
            }
            else {
                res.send(countryMapping);
            }
        }
        catch (err) {
            logger_1.default.warn('Country mapping was requested but was not found in the selected config file. Take a look at the fbctf.yml config file to find out how to configure the country mappings required by FBCTF.');
            res.status(500).send();
        }
    };
}
exports.countryMapping = countryMapping;
//# sourceMappingURL=countryMapping.js.map