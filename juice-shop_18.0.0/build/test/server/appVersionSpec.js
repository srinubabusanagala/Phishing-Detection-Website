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
const config_1 = __importDefault(require("config"));
const chai_1 = __importDefault(require("chai"));
const sinon_chai_1 = __importDefault(require("sinon-chai"));
const package_json_1 = require("../../package.json");
const appVersion_1 = require("../../routes/appVersion");
const expect = chai_1.default.expect;
chai_1.default.use(sinon_chai_1.default);
describe('appVersion', () => {
    let req;
    let res;
    it('should ' + config_1.default.get('application.showVersionNumber') ? '' : 'not ' + 'return version specified in package.json', () => {
        req = {};
        res = { json: sinon_1.default.spy() };
        (0, appVersion_1.retrieveAppVersion)()(req, res);
        expect(res.json).to.have.been.calledWith({ version: config_1.default.get('application.showVersionNumber') ? package_json_1.version : '' });
    });
});
//# sourceMappingURL=appVersionSpec.js.map