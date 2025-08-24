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
exports.deluxeMembershipStatus = exports.upgradeToDeluxe = void 0;
const challengeUtils = __importStar(require("../lib/challengeUtils"));
const wallet_1 = require("../models/wallet");
const datacache_1 = require("../data/datacache");
const security = __importStar(require("../lib/insecurity"));
const user_1 = require("../models/user");
const card_1 = require("../models/card");
const utils = __importStar(require("../lib/utils"));
function upgradeToDeluxe() {
    return async (req, res, next) => {
        try {
            const user = await user_1.UserModel.findOne({ where: { id: req.body.UserId, role: security.roles.customer } });
            if (user == null) {
                res.status(400).json({ status: 'error', error: 'Something went wrong. Please try again!' });
                return;
            }
            if (req.body.paymentMode === 'wallet') {
                const wallet = await wallet_1.WalletModel.findOne({ where: { UserId: req.body.UserId } });
                if ((wallet != null) && wallet.balance < 49) {
                    res.status(400).json({ status: 'error', error: 'Insuffienct funds in Wallet' });
                    return;
                }
                else {
                    await wallet_1.WalletModel.decrement({ balance: 49 }, { where: { UserId: req.body.UserId } });
                }
            }
            if (req.body.paymentMode === 'card') {
                const card = await card_1.CardModel.findOne({ where: { id: req.body.paymentId, UserId: req.body.UserId } });
                if ((card == null) || card.expYear < new Date().getFullYear() || (card.expYear === new Date().getFullYear() && card.expMonth - 1 < new Date().getMonth())) {
                    res.status(400).json({ status: 'error', error: 'Invalid Card' });
                    return;
                }
            }
            try {
                const updatedUser = await user.update({ role: security.roles.deluxe, deluxeToken: security.deluxeToken(user.email) });
                challengeUtils.solveIf(datacache_1.challenges.freeDeluxeChallenge, () => {
                    return security.verify(utils.jwtFrom(req)) && req.body.paymentMode !== 'wallet' && req.body.paymentMode !== 'card';
                });
                const userWithStatus = utils.queryResultToJson(updatedUser);
                const updatedToken = security.authorize(userWithStatus);
                security.authenticatedUsers.put(updatedToken, userWithStatus);
                res.status(200).json({ status: 'success', data: { confirmation: 'Congratulations! You are now a deluxe member!', token: updatedToken } });
            }
            catch (error) {
                res.status(400).json({ status: 'error', error: 'Something went wrong. Please try again!' });
            }
        }
        catch (err) {
            res.status(400).json({ status: 'error', error: 'Something went wrong: ' + utils.getErrorMessage(err) });
        }
    };
}
exports.upgradeToDeluxe = upgradeToDeluxe;
function deluxeMembershipStatus() {
    return (req, res, next) => {
        if (security.isCustomer(req)) {
            res.status(200).json({ status: 'success', data: { membershipCost: 49 } });
        }
        else if (security.isDeluxe(req)) {
            res.status(400).json({ status: 'error', error: 'You are already a deluxe member!' });
        }
        else {
            res.status(400).json({ status: 'error', error: 'You are not eligible for deluxe membership!' });
        }
    };
}
exports.deluxeMembershipStatus = deluxeMembershipStatus;
//# sourceMappingURL=deluxe.js.map