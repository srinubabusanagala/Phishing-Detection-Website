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
const angular_1 = require("../../routes/angular");
const expect = chai_1.default.expect;
chai_1.default.use(sinon_chai_1.default);
describe('angular', () => {
    let req;
    let res;
    let next;
    beforeEach(() => {
        req = {};
        res = { sendFile: sinon_1.default.spy() };
        next = sinon_1.default.spy();
    });
    it('should serve index.html for any URL', () => {
        req.url = '/any/thing';
        (0, angular_1.serveAngularClient)()(req, res, next);
        expect(res.sendFile).to.have.been.calledWith(sinon_1.default.match(/index\.html/));
    });
    it('should raise error for /api endpoint URL', () => {
        req.url = '/api';
        (0, angular_1.serveAngularClient)()(req, res, next);
        expect(res.sendFile).to.have.not.been.calledWith(sinon_1.default.match.any);
        expect(next).to.have.been.calledWith(sinon_1.default.match.instanceOf(Error));
    });
    it('should raise error for /rest endpoint URL', () => {
        req.url = '/rest';
        (0, angular_1.serveAngularClient)()(req, res, next);
        expect(res.sendFile).to.have.not.been.calledWith(sinon_1.default.match.any);
        expect(next).to.have.been.calledWith(sinon_1.default.match.instanceOf(Error));
    });
});
//# sourceMappingURL=angularSpec.js.map