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
const premiumReward_1 = require("../../routes/premiumReward");
const expect = chai_1.default.expect;
chai_1.default.use(sinon_chai_1.default);
describe('premiumReward', () => {
    let req;
    let res;
    let save;
    beforeEach(() => {
        res = { sendFile: sinon_1.default.spy() };
        req = {};
        save = () => ({
            then() { }
        });
    });
    it('should serve /frontend/dist/frontend/assets/private/JuiceShop_Wallpaper_1920x1080_VR.jpg', () => {
        (0, premiumReward_1.servePremiumContent)()(req, res);
        expect(res.sendFile).to.have.been.calledWith(sinon_1.default.match(/frontend[/\\]dist[/\\]frontend[/\\]assets[/\\]private[/\\]JuiceShop_Wallpaper_1920x1080_VR\.jpg/));
    });
    it('should solve "premiumPaywallChallenge"', () => {
        datacache_1.challenges.premiumPaywallChallenge = { solved: false, save };
        (0, premiumReward_1.servePremiumContent)()(req, res);
        expect(datacache_1.challenges.premiumPaywallChallenge.solved).to.equal(true);
    });
});
//# sourceMappingURL=premiumRewardSpec.js.map