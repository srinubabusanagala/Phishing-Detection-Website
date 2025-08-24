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
const config_1 = __importDefault(require("config"));
const appConfiguration_1 = require("../../routes/appConfiguration");
const expect = chai_1.default.expect;
chai_1.default.use(sinon_chai_1.default);
describe('appConfiguration', () => {
    let req;
    let res;
    it('should return configuration object', () => {
        req = {};
        res = { json: sinon_1.default.spy() };
        (0, appConfiguration_1.retrieveAppConfiguration)()(req, res);
        expect(res.json).to.have.been.calledWith({ config: config_1.default });
    });
});
//# sourceMappingURL=appConfigurationSpec.js.map