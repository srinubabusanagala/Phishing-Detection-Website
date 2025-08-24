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
const redirect_1 = require("../../routes/redirect");
const insecurity_1 = require("../../lib/insecurity");
const expect = chai_1.default.expect;
chai_1.default.use(sinon_chai_1.default);
describe('redirect', () => {
    let req;
    let res;
    let next;
    let save;
    beforeEach(() => {
        req = { query: {} };
        res = { redirect: sinon_1.default.spy(), status: sinon_1.default.spy() };
        next = sinon_1.default.spy();
        save = () => ({
            then() { }
        });
    });
    describe('should be performed for all allowlisted URLs', () => {
        for (const url of insecurity_1.redirectAllowlist) {
            it(url, () => {
                req.query.to = url;
                (0, redirect_1.performRedirect)()(req, res, next);
                expect(res.redirect).to.have.been.calledWith(url);
            });
        }
    });
    it('should raise error for URL not on allowlist', () => {
        req.query.to = 'http://kimminich.de';
        (0, redirect_1.performRedirect)()(req, res, next);
        expect(res.redirect).to.have.not.been.calledWith(sinon_1.default.match.any);
        expect(next).to.have.been.calledWith(sinon_1.default.match.instanceOf(Error));
    });
    it('redirecting to https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm should solve the "redirectCryptoCurrencyChallenge"', () => {
        req.query.to = 'https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm';
        datacache_1.challenges.redirectCryptoCurrencyChallenge = { solved: false, save };
        (0, redirect_1.performRedirect)()(req, res, next);
        expect(datacache_1.challenges.redirectCryptoCurrencyChallenge.solved).to.equal(true);
    });
    it('redirecting to https://explorer.dash.org/address/Xr556RzuwX6hg5EGpkybbv5RanJoZN17kW should solve the "redirectCryptoCurrencyChallenge"', () => {
        req.query.to = 'https://explorer.dash.org/address/Xr556RzuwX6hg5EGpkybbv5RanJoZN17kW';
        datacache_1.challenges.redirectCryptoCurrencyChallenge = { solved: false, save };
        (0, redirect_1.performRedirect)()(req, res, next);
        expect(datacache_1.challenges.redirectCryptoCurrencyChallenge.solved).to.equal(true);
    });
    it('redirecting to https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6 should solve the "redirectCryptoCurrencyChallenge"', () => {
        req.query.to = 'https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6';
        datacache_1.challenges.redirectCryptoCurrencyChallenge = { solved: false, save };
        (0, redirect_1.performRedirect)()(req, res, next);
        expect(datacache_1.challenges.redirectCryptoCurrencyChallenge.solved).to.equal(true);
    });
    it('tricking the allowlist should solve "redirectChallenge"', () => {
        req.query.to = 'http://kimminich.de?to=https://github.com/juice-shop/juice-shop';
        datacache_1.challenges.redirectChallenge = { solved: false, save };
        (0, redirect_1.performRedirect)()(req, res, next);
        expect(datacache_1.challenges.redirectChallenge.solved).to.equal(true);
    });
});
//# sourceMappingURL=redirectSpec.js.map