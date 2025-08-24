"use strict";
/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.continueCodeFixIt = exports.continueCodeFindIt = exports.continueCode = void 0;
const cjs_1 = __importDefault(require("hashids/cjs"));
const challenge_1 = require("../models/challenge");
const datacache_1 = require("../data/datacache");
const sequelize_1 = require("sequelize");
function continueCode() {
    const hashids = new cjs_1.default('this is my salt', 60, 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890');
    return (req, res) => {
        const ids = [];
        for (const challenge of Object.values(datacache_1.challenges)) {
            if (challenge.solved)
                ids.push(challenge.id);
        }
        const continueCode = ids.length > 0 ? hashids.encode(ids) : undefined;
        res.json({ continueCode });
    };
}
exports.continueCode = continueCode;
function continueCodeFindIt() {
    const hashids = new cjs_1.default('this is the salt for findIt challenges', 60, 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890');
    return async (req, res) => {
        const ids = [];
        const challenges = await challenge_1.ChallengeModel.findAll({ where: { codingChallengeStatus: { [sequelize_1.Op.gte]: 1 } } });
        for (const challenge of challenges) {
            ids.push(challenge.id);
        }
        const continueCode = ids.length > 0 ? hashids.encode(ids) : undefined;
        res.json({ continueCode });
    };
}
exports.continueCodeFindIt = continueCodeFindIt;
function continueCodeFixIt() {
    const hashids = new cjs_1.default('yet another salt for the fixIt challenges', 60, 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890');
    return async (req, res) => {
        const ids = [];
        const challenges = await challenge_1.ChallengeModel.findAll({ where: { codingChallengeStatus: { [sequelize_1.Op.gte]: 2 } } });
        for (const challenge of challenges) {
            ids.push(challenge.id);
        }
        const continueCode = ids.length > 0 ? hashids.encode(ids) : undefined;
        res.json({ continueCode });
    };
}
exports.continueCodeFixIt = continueCodeFixIt;
//# sourceMappingURL=continueCode.js.map