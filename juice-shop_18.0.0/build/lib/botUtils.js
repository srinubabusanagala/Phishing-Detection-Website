"use strict";
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
exports.testFunction = exports.couponCode = exports.productPrice = void 0;
/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
const product_1 = require("../models/product");
const fuzzball_1 = __importDefault(require("fuzzball"));
const datacache_1 = require("../data/datacache");
const security = __importStar(require("./insecurity"));
const challengeUtils = __importStar(require("./challengeUtils"));
async function productPrice(query, user) {
    const products = await product_1.ProductModel.findAll();
    const queriedProducts = products
        .filter((product) => fuzzball_1.default.partial_ratio(query, product.name) > 60)
        .map((product) => `${product.name} costs ${product.price}¤`);
    return {
        action: 'response',
        body: queriedProducts.length > 0 ? queriedProducts.join(', ') : 'Sorry I couldn\'t find any products with that name'
    };
}
exports.productPrice = productPrice;
function couponCode(query, user) {
    challengeUtils.solveIf(datacache_1.challenges.bullyChatbotChallenge, () => { return true; });
    return {
        action: 'response',
        body: `Oooookay, if you promise to stop nagging me here's a 10% coupon code for you: ${security.generateCoupon(10)}`
    };
}
exports.couponCode = couponCode;
function testFunction(query, user) {
    return {
        action: 'response',
        body: '3be2e438b7f3d04c89d7749f727bb3bd'
    };
}
exports.testFunction = testFunction;
//# sourceMappingURL=botUtils.js.map