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
exports.getDeliveryMethod = exports.getDeliveryMethods = void 0;
const delivery_1 = require("../models/delivery");
const security = __importStar(require("../lib/insecurity"));
function getDeliveryMethods() {
    return async (req, res, next) => {
        const methods = await delivery_1.DeliveryModel.findAll();
        if (methods) {
            const sendMethods = [];
            for (const method of methods) {
                sendMethods.push({
                    id: method.id,
                    name: method.name,
                    price: security.isDeluxe(req) ? method.deluxePrice : method.price,
                    eta: method.eta,
                    icon: method.icon
                });
            }
            res.status(200).json({ status: 'success', data: sendMethods });
        }
        else {
            res.status(400).json({ status: 'error' });
        }
    };
}
exports.getDeliveryMethods = getDeliveryMethods;
function getDeliveryMethod() {
    return async (req, res, next) => {
        const method = await delivery_1.DeliveryModel.findOne({ where: { id: req.params.id } });
        if (method != null) {
            const sendMethod = {
                id: method.id,
                name: method.name,
                price: security.isDeluxe(req) ? method.deluxePrice : method.price,
                eta: method.eta,
                icon: method.icon
            };
            res.status(200).json({ status: 'success', data: sendMethod });
        }
        else {
            res.status(400).json({ status: 'error' });
        }
    };
}
exports.getDeliveryMethod = getDeliveryMethod;
//# sourceMappingURL=delivery.js.map