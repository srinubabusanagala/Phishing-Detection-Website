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
exports.retrieveBasket = void 0;
const product_1 = require("../models/product");
const basket_1 = require("../models/basket");
const challengeUtils = __importStar(require("../lib/challengeUtils"));
const utils = __importStar(require("../lib/utils"));
const security = __importStar(require("../lib/insecurity"));
const datacache_1 = require("../data/datacache");
function retrieveBasket() {
    return (req, res, next) => {
        const id = req.params.id;
        basket_1.BasketModel.findOne({ where: { id }, include: [{ model: product_1.ProductModel, paranoid: false, as: 'Products' }] })
            .then((basket) => {
            /* jshint eqeqeq:false */
            challengeUtils.solveIf(datacache_1.challenges.basketAccessChallenge, () => {
                const user = security.authenticatedUsers.from(req);
                return user && id && id !== 'undefined' && id !== 'null' && id !== 'NaN' && user.bid && user?.bid != parseInt(id, 10); // eslint-disable-line eqeqeq
            });
            if (((basket?.Products) != null) && basket.Products.length > 0) {
                for (let i = 0; i < basket.Products.length; i++) {
                    basket.Products[i].name = req.__(basket.Products[i].name);
                }
            }
            res.json(utils.queryResultToJson(basket));
        }).catch((error) => {
            next(error);
        });
    };
}
exports.retrieveBasket = retrieveBasket;
//# sourceMappingURL=basket.js.map