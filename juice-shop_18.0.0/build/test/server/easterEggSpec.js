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
const easterEgg_1 = require("../../routes/easterEgg");
const expect = chai_1.default.expect;
chai_1.default.use(sinon_chai_1.default);
describe('easterEgg', () => {
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
    it('should serve /frontend/dist/frontend/assets/private/threejs-demo.html', () => {
        (0, easterEgg_1.serveEasterEgg)()(req, res);
        expect(res.sendFile).to.have.been.calledWith(sinon_1.default.match(/frontend[/\\]dist[/\\]frontend[/\\]assets[/\\]private[/\\]threejs-demo\.html/));
    });
    it('should solve "easterEggLevelTwoChallenge"', () => {
        datacache_1.challenges.easterEggLevelTwoChallenge = { solved: false, save };
        (0, easterEgg_1.serveEasterEgg)()(req, res);
        expect(datacache_1.challenges.easterEggLevelTwoChallenge.solved).to.equal(true);
    });
});
//# sourceMappingURL=easterEggSpec.js.map