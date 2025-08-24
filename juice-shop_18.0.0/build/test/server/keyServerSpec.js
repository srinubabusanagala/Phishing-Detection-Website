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
const keyServer_1 = require("../../routes/keyServer");
const expect = chai_1.default.expect;
chai_1.default.use(sinon_chai_1.default);
describe('keyServer', () => {
    let req;
    let res;
    let next;
    beforeEach(() => {
        req = { params: {} };
        res = { sendFile: sinon_1.default.spy(), status: sinon_1.default.spy() };
        next = sinon_1.default.spy();
    });
    it('should serve requested file from folder /encryptionkeys', () => {
        req.params.file = 'test.file';
        (0, keyServer_1.serveKeyFiles)()(req, res, next);
        expect(res.sendFile).to.have.been.calledWith(sinon_1.default.match(/encryptionkeys[/\\]test.file/));
    });
    it('should raise error for slashes in filename', () => {
        req.params.file = '../../../../nice.try';
        (0, keyServer_1.serveKeyFiles)()(req, res, next);
        expect(res.sendFile).to.have.not.been.calledWith(sinon_1.default.match.any);
        expect(next).to.have.been.calledWith(sinon_1.default.match.instanceOf(Error));
    });
});
//# sourceMappingURL=keyServerSpec.js.map