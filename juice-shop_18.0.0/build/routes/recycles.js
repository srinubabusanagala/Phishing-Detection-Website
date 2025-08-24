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
exports.blockRecycleItems = exports.getRecycleItem = void 0;
const recycle_1 = require("../models/recycle");
const utils = __importStar(require("../lib/utils"));
const getRecycleItem = () => (req, res) => {
    recycle_1.RecycleModel.findAll({
        where: {
            id: JSON.parse(req.params.id)
        }
    }).then((Recycle) => {
        return res.send(utils.queryResultToJson(Recycle));
    }).catch((_) => {
        return res.send('Error fetching recycled items. Please try again');
    });
};
exports.getRecycleItem = getRecycleItem;
const blockRecycleItems = () => (req, res) => {
    const errMsg = { err: 'Sorry, this endpoint is not supported.' };
    return res.send(utils.queryResultToJson(errMsg));
};
exports.blockRecycleItems = blockRecycleItems;
//# sourceMappingURL=recycles.js.map