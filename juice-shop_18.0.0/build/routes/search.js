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
exports.searchProducts = void 0;
const utils = __importStar(require("../lib/utils"));
const models = __importStar(require("../models/index"));
const user_1 = require("../models/user");
const datacache_1 = require("../data/datacache");
const challengeUtils = __importStar(require("../lib/challengeUtils"));
class ErrorWithParent extends Error {
}
// vuln-code-snippet start unionSqlInjectionChallenge dbSchemaChallenge
function searchProducts() {
    return (req, res, next) => {
        let criteria = req.query.q === 'undefined' ? '' : req.query.q ?? '';
        criteria = (criteria.length <= 200) ? criteria : criteria.substring(0, 200);
        models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`) // vuln-code-snippet vuln-line unionSqlInjectionChallenge dbSchemaChallenge
            .then(([products]) => {
            const dataString = JSON.stringify(products);
            if (challengeUtils.notSolved(datacache_1.challenges.unionSqlInjectionChallenge)) { // vuln-code-snippet hide-start
                let solved = true;
                user_1.UserModel.findAll().then(data => {
                    const users = utils.queryResultToJson(data);
                    if (users.data?.length) {
                        for (let i = 0; i < users.data.length; i++) {
                            solved = solved && utils.containsOrEscaped(dataString, users.data[i].email) && utils.contains(dataString, users.data[i].password);
                            if (!solved) {
                                break;
                            }
                        }
                        if (solved) {
                            challengeUtils.solve(datacache_1.challenges.unionSqlInjectionChallenge);
                        }
                    }
                }).catch((error) => {
                    next(error);
                });
            }
            if (challengeUtils.notSolved(datacache_1.challenges.dbSchemaChallenge)) {
                let solved = true;
                void models.sequelize.query('SELECT sql FROM sqlite_master').then(([data]) => {
                    const tableDefinitions = utils.queryResultToJson(data);
                    if (tableDefinitions.data?.length) {
                        for (let i = 0; i < tableDefinitions.data.length; i++) {
                            if (tableDefinitions.data[i].sql) {
                                solved = solved && utils.containsOrEscaped(dataString, tableDefinitions.data[i].sql);
                                if (!solved) {
                                    break;
                                }
                            }
                        }
                        if (solved) {
                            challengeUtils.solve(datacache_1.challenges.dbSchemaChallenge);
                        }
                    }
                });
            } // vuln-code-snippet hide-end
            for (let i = 0; i < products.length; i++) {
                products[i].name = req.__(products[i].name);
                products[i].description = req.__(products[i].description);
            }
            res.json(utils.queryResultToJson(products));
        }).catch((error) => {
            next(error.parent);
        });
    };
}
exports.searchProducts = searchProducts;
// vuln-code-snippet end unionSqlInjectionChallenge dbSchemaChallenge
//# sourceMappingURL=search.js.map