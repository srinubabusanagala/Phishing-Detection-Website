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
const countryMapping_1 = require("../../routes/countryMapping");
const expect = chai_1.default.expect;
chai_1.default.use(sinon_chai_1.default);
describe('countryMapping', () => {
    let req;
    let res;
    beforeEach(() => {
        req = {};
        res = { send: sinon_1.default.spy(), status: sinon_1.default.stub().returns({ send: sinon_1.default.spy() }) };
    });
    it('should return configured country mappings', () => {
        (0, countryMapping_1.countryMapping)({ get: sinon_1.default.stub().withArgs('ctf.countryMapping').returns('TEST') })(req, res);
        expect(res.send).to.have.been.calledWith('TEST');
    });
    it('should return server error when configuration has no country mappings', () => {
        (0, countryMapping_1.countryMapping)({ get: sinon_1.default.stub().withArgs('ctf.countryMapping').returns(null) })(req, res);
        expect(res.status).to.have.been.calledWith(500);
    });
    it('should return ' + (config_1.default.get('ctf.countryMapping') ? 'no ' : '') + 'server error for active configuration from config/' + process.env.NODE_ENV + '.yml', () => {
        (0, countryMapping_1.countryMapping)()(req, res);
        if (config_1.default.get('ctf.countryMapping')) {
            expect(res.send).to.have.been.calledWith(config_1.default.get('ctf.countryMapping'));
        }
        else {
            expect(res.status).to.have.been.calledWith(500);
        }
    });
});
//# sourceMappingURL=countryMappingSpec.js.map