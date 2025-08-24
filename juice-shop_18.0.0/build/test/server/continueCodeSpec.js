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
const continueCode_1 = require("../../routes/continueCode");
const expect = chai_1.default.expect;
chai_1.default.use(sinon_chai_1.default);
describe('continueCode', () => {
    let req;
    let res;
    beforeEach(() => {
        req = {};
        res = { json: sinon_1.default.spy() };
    });
    it('should be empty when no challenges are solved', () => {
        datacache_1.challenges.scoreBoardChallenge = { solved: false };
        datacache_1.challenges.adminSectionChallenge = { solved: false };
        (0, continueCode_1.continueCode)()(req, res);
        expect(res.json).to.have.been.calledWith({ continueCode: undefined });
    });
    it('should be hashid value of IDs of solved challenges', () => {
        datacache_1.challenges.scoreBoardChallenge = { id: 1, solved: true };
        datacache_1.challenges.adminSectionChallenge = { id: 2, solved: true };
        datacache_1.challenges.continueCodeChallenge = { id: 3, solved: false };
        (0, continueCode_1.continueCode)()(req, res);
        expect(res.json).to.have.been.calledWith({ continueCode: 'yXjv6Z5jWJnzD6a3YvmwPRXK7roAyzHDde2Og19yEN84plqxkMBbLVQrDeoY' });
    });
});
//# sourceMappingURL=continueCodeSpec.js.map