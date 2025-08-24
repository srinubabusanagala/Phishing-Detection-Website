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
exports.updateProductReviews = void 0;
const challengeUtils = __importStar(require("../lib/challengeUtils"));
const datacache_1 = require("../data/datacache");
const security = __importStar(require("../lib/insecurity"));
const db = __importStar(require("../data/mongodb"));
// vuln-code-snippet start noSqlReviewsChallenge forgedReviewChallenge
function updateProductReviews() {
    return (req, res, next) => {
        const user = security.authenticatedUsers.from(req); // vuln-code-snippet vuln-line forgedReviewChallenge
        db.reviewsCollection.update(// vuln-code-snippet neutral-line forgedReviewChallenge
        { _id: req.body.id }, // vuln-code-snippet vuln-line noSqlReviewsChallenge forgedReviewChallenge
        { $set: { message: req.body.message } }, { multi: true } // vuln-code-snippet vuln-line noSqlReviewsChallenge
        ).then((result) => {
            challengeUtils.solveIf(datacache_1.challenges.noSqlReviewsChallenge, () => { return result.modified > 1; }); // vuln-code-snippet hide-line
            challengeUtils.solveIf(datacache_1.challenges.forgedReviewChallenge, () => { return user?.data && result.original[0] && result.original[0].author !== user.data.email && result.modified === 1; }); // vuln-code-snippet hide-line
            res.json(result);
        }, (err) => {
            res.status(500).json(err);
        });
    };
}
exports.updateProductReviews = updateProductReviews;
// vuln-code-snippet end noSqlReviewsChallenge forgedReviewChallenge
//# sourceMappingURL=updateProductReviews.js.map