"use strict";
/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.addWalletBalance = exports.getWalletBalance = void 0;
const wallet_1 = require("../models/wallet");
const card_1 = require("../models/card");
function getWalletBalance() {
    return async (req, res, next) => {
        const wallet = await wallet_1.WalletModel.findOne({ where: { UserId: req.body.UserId } });
        if (wallet != null) {
            res.status(200).json({ status: 'success', data: wallet.balance });
        }
        else {
            res.status(404).json({ status: 'error' });
        }
    };
}
exports.getWalletBalance = getWalletBalance;
function addWalletBalance() {
    return async (req, res, next) => {
        const cardId = req.body.paymentId;
        const card = cardId ? await card_1.CardModel.findOne({ where: { id: cardId, UserId: req.body.UserId } }) : null;
        if (card != null) {
            wallet_1.WalletModel.increment({ balance: req.body.balance }, { where: { UserId: req.body.UserId } }).then(() => {
                res.status(200).json({ status: 'success', data: req.body.balance });
            }).catch(() => {
                res.status(404).json({ status: 'error' });
            });
        }
        else {
            res.status(402).json({ status: 'error', message: 'Payment not accepted.' });
        }
    };
}
exports.addWalletBalance = addWalletBalance;
//# sourceMappingURL=wallet.js.map