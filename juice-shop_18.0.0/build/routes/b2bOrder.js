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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.b2bOrder = void 0;
const node_vm_1 = __importDefault(require("node:vm"));
// @ts-expect-error FIXME due to non-existing type definitions for notevil
const notevil_1 = require("notevil");
const challengeUtils = __importStar(require("../lib/challengeUtils"));
const datacache_1 = require("../data/datacache");
const security = __importStar(require("../lib/insecurity"));
const utils = __importStar(require("../lib/utils"));
function b2bOrder() {
    return ({ body }, res, next) => {
        if (utils.isChallengeEnabled(datacache_1.challenges.rceChallenge) || utils.isChallengeEnabled(datacache_1.challenges.rceOccupyChallenge)) {
            const orderLinesData = body.orderLinesData || '';
            try {
                const sandbox = { safeEval: notevil_1.eval, orderLinesData };
                node_vm_1.default.createContext(sandbox);
                node_vm_1.default.runInContext('safeEval(orderLinesData)', sandbox, { timeout: 2000 });
                res.json({ cid: body.cid, orderNo: uniqueOrderNumber(), paymentDue: dateTwoWeeksFromNow() });
            }
            catch (err) {
                if (utils.getErrorMessage(err).match(/Script execution timed out.*/) != null) {
                    challengeUtils.solveIf(datacache_1.challenges.rceOccupyChallenge, () => { return true; });
                    res.status(503);
                    next(new Error('Sorry, we are temporarily not available! Please try again later.'));
                }
                else {
                    challengeUtils.solveIf(datacache_1.challenges.rceChallenge, () => { return utils.getErrorMessage(err) === 'Infinite loop detected - reached max iterations'; });
                    next(err);
                }
            }
        }
        else {
            res.json({ cid: body.cid, orderNo: uniqueOrderNumber(), paymentDue: dateTwoWeeksFromNow() });
        }
    };
    function uniqueOrderNumber() {
        return security.hash(`${(new Date()).toString()}_B2B`);
    }
    function dateTwoWeeksFromNow() {
        return new Date(new Date().getTime() + (14 * 24 * 60 * 60 * 1000)).toISOString();
    }
}
exports.b2bOrder = b2bOrder;
//# sourceMappingURL=b2bOrder.js.map