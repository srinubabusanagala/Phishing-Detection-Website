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
exports.likeProductReviews = void 0;
const challengeUtils = __importStar(require("../lib/challengeUtils"));
const datacache_1 = require("../data/datacache");
const security = __importStar(require("../lib/insecurity"));
const db = __importStar(require("../data/mongodb"));
const sleep = async (ms) => await new Promise(resolve => setTimeout(resolve, ms));
function likeProductReviews() {
    return async (req, res, next) => {
        const id = req.body.id;
        const user = security.authenticatedUsers.from(req);
        if (!user) {
            return res.status(401).json({ error: 'Unauthorized' });
        }
        try {
            const review = await db.reviewsCollection.findOne({ _id: id });
            if (!review) {
                return res.status(404).json({ error: 'Not found' });
            }
            const likedBy = review.likedBy;
            if (likedBy.includes(user.data.email)) {
                return res.status(403).json({ error: 'Not allowed' });
            }
            await db.reviewsCollection.update({ _id: id }, { $inc: { likesCount: 1 } });
            // Artificial wait for timing attack challenge
            await sleep(150);
            try {
                const updatedReview = await db.reviewsCollection.findOne({ _id: id });
                const updatedLikedBy = updatedReview.likedBy;
                updatedLikedBy.push(user.data.email);
                const count = updatedLikedBy.filter(email => email === user.data.email).length;
                challengeUtils.solveIf(datacache_1.challenges.timingAttackChallenge, () => count > 2);
                const result = await db.reviewsCollection.update({ _id: id }, { $set: { likedBy: updatedLikedBy } });
                res.json(result);
            }
            catch (err) {
                res.status(500).json(err);
            }
        }
        catch (err) {
            res.status(400).json({ error: 'Wrong Params' });
        }
    };
}
exports.likeProductReviews = likeProductReviews;
//# sourceMappingURL=likeProductReviews.js.map