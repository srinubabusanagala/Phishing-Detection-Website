"use strict";
/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const sinon_1 = __importDefault(require("sinon"));
const chai_1 = __importDefault(require("chai"));
const sinon_chai_1 = __importDefault(require("sinon-chai"));
const datacache_1 = require("../../data/datacache");
const b2bOrder_1 = require("../../routes/b2bOrder");
const expect = chai_1.default.expect;
chai_1.default.use(sinon_chai_1.default);
describe('b2bOrder', () => {
    let req;
    let res;
    let next;
    let save;
    beforeEach(() => {
        req = { body: {} };
        res = { json: sinon_1.default.spy(), status: sinon_1.default.spy() };
        next = sinon_1.default.spy();
        save = () => ({
            then() { }
        });
        datacache_1.challenges.rceChallenge = { solved: false, save };
    });
    xit('infinite loop payload does not succeed but solves "rceChallenge"', () => {
        req.body.orderLinesData = '(function dos() { while(true); })()';
        (0, b2bOrder_1.b2bOrder)()(req, res, next);
        expect(datacache_1.challenges.rceChallenge.solved).to.equal(true);
    });
    // FIXME Disabled as test started failing on Linux regularly
    xit('timeout after 2 seconds solves "rceOccupyChallenge"', () => {
        req.body.orderLinesData = '/((a+)+)b/.test("aaaaaaaaaaaaaaaaaaaaaaaaaaaaa")';
        (0, b2bOrder_1.b2bOrder)()(req, res, next);
        expect(datacache_1.challenges.rceOccupyChallenge.solved).to.equal(true);
    } /*, 3000 */);
    it('deserializing JSON as documented in Swagger should not solve "rceChallenge"', () => {
        req.body.orderLinesData = '{"productId": 12,"quantity": 10000,"customerReference": ["PO0000001.2", "SM20180105|042"],"couponCode": "pes[Bh.u*t"}';
        (0, b2bOrder_1.b2bOrder)()(req, res, next);
        expect(datacache_1.challenges.rceChallenge.solved).to.equal(false);
    });
    it('deserializing arbitrary JSON should not solve "rceChallenge"', () => {
        req.body.orderLinesData = '{"hello": "world", "foo": 42, "bar": [false, true]}';
        (0, b2bOrder_1.b2bOrder)()(req, res, next);
        expect(datacache_1.challenges.rceChallenge.solved).to.equal(false);
    });
    it('deserializing broken JSON should not solve "rceChallenge"', () => {
        req.body.orderLinesData = '{ "productId: 28';
        (0, b2bOrder_1.b2bOrder)()(req, res, next);
        expect(datacache_1.challenges.rceChallenge.solved).to.equal(false);
    });
});
//# sourceMappingURL=b2bOrderSpec.js.map