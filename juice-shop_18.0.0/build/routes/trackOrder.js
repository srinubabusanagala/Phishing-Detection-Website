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
exports.trackOrder = void 0;
const utils = __importStar(require("../lib/utils"));
const challengeUtils = __importStar(require("../lib/challengeUtils"));
const db = __importStar(require("../data/mongodb"));
const datacache_1 = require("../data/datacache");
function trackOrder() {
    return (req, res) => {
        // Truncate id to avoid unintentional RCE
        const id = !utils.isChallengeEnabled(datacache_1.challenges.reflectedXssChallenge) ? String(req.params.id).replace(/[^\w-]+/g, '') : utils.trunc(req.params.id, 60);
        challengeUtils.solveIf(datacache_1.challenges.reflectedXssChallenge, () => { return utils.contains(id, '<iframe src="javascript:alert(`xss`)">'); });
        db.ordersCollection.find({ $where: `this.orderId === '${id}'` }).then((order) => {
            const result = utils.queryResultToJson(order);
            challengeUtils.solveIf(datacache_1.challenges.noSqlOrdersChallenge, () => { return result.data.length > 1; });
            if (result.data[0] === undefined) {
                result.data[0] = { orderId: id };
            }
            res.json(result);
        }, () => {
            res.status(400).json({ error: 'Wrong Param' });
        });
    };
}
exports.trackOrder = trackOrder;
//# sourceMappingURL=trackOrder.js.map