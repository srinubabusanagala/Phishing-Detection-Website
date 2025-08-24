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
exports.dataExport = void 0;
const challengeUtils = __importStar(require("../lib/challengeUtils"));
const memory_1 = require("../models/memory");
const datacache_1 = require("../data/datacache");
const security = __importStar(require("../lib/insecurity"));
const db = __importStar(require("../data/mongodb"));
function dataExport() {
    return async (req, res, next) => {
        const loggedInUser = security.authenticatedUsers.get(req.headers?.authorization?.replace('Bearer ', ''));
        if (loggedInUser?.data?.email && loggedInUser.data.id) {
            const username = loggedInUser.data.username;
            const email = loggedInUser.data.email;
            const updatedEmail = email.replace(/[aeiou]/gi, '*');
            const userData = {
                username,
                email,
                orders: [],
                reviews: [],
                memories: []
            };
            const memories = await memory_1.MemoryModel.findAll({ where: { UserId: req.body.UserId } });
            memories.forEach((memory) => {
                userData.memories.push({
                    imageUrl: req.protocol + '://' + req.get('host') + '/' + memory.imagePath,
                    caption: memory.caption
                });
            });
            db.ordersCollection.find({ email: updatedEmail }).then((orders) => {
                if (orders.length > 0) {
                    orders.forEach(order => {
                        userData.orders.push({
                            orderId: order.orderId,
                            totalPrice: order.totalPrice,
                            products: [...order.products],
                            bonus: order.bonus,
                            eta: order.eta
                        });
                    });
                }
                db.reviewsCollection.find({ author: email }).then((reviews) => {
                    if (reviews.length > 0) {
                        reviews.forEach(review => {
                            userData.reviews.push({
                                message: review.message,
                                author: review.author,
                                productId: review.product,
                                likesCount: review.likesCount,
                                likedBy: review.likedBy
                            });
                        });
                    }
                    const emailHash = security.hash(email).slice(0, 4);
                    for (const order of userData.orders) {
                        challengeUtils.solveIf(datacache_1.challenges.dataExportChallenge, () => { return order.orderId.split('-')[0] !== emailHash; });
                    }
                    res.status(200).send({ userData: JSON.stringify(userData, null, 2), confirmation: 'Your data export will open in a new Browser window.' });
                }, () => {
                    next(new Error(`Error retrieving reviews for ${updatedEmail}`));
                });
            }, () => {
                next(new Error(`Error retrieving orders for ${updatedEmail}`));
            });
        }
        else {
            next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress));
        }
    };
}
exports.dataExport = dataExport;
//# sourceMappingURL=dataExport.js.map