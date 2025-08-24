"use strict";
/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.delAddressById = exports.getAddressById = exports.getAddress = void 0;
const address_1 = require("../models/address");
function getAddress() {
    return async (req, res) => {
        const addresses = await address_1.AddressModel.findAll({ where: { UserId: req.body.UserId } });
        res.status(200).json({ status: 'success', data: addresses });
    };
}
exports.getAddress = getAddress;
function getAddressById() {
    return async (req, res) => {
        const address = await address_1.AddressModel.findOne({ where: { id: req.params.id, UserId: req.body.UserId } });
        if (address != null) {
            res.status(200).json({ status: 'success', data: address });
        }
        else {
            res.status(400).json({ status: 'error', data: 'Malicious activity detected.' });
        }
    };
}
exports.getAddressById = getAddressById;
function delAddressById() {
    return async (req, res) => {
        const address = await address_1.AddressModel.destroy({ where: { id: req.params.id, UserId: req.body.UserId } });
        if (address) {
            res.status(200).json({ status: 'success', data: 'Address deleted successfully.' });
        }
        else {
            res.status(400).json({ status: 'error', data: 'Malicious activity detected.' });
        }
    };
}
exports.delAddressById = delAddressById;
//# sourceMappingURL=address.js.map