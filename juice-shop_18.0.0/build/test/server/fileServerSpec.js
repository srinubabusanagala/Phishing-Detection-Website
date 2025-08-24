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
const fileServer_1 = require("../../routes/fileServer");
const expect = chai_1.default.expect;
chai_1.default.use(sinon_chai_1.default);
describe('fileServer', () => {
    let req;
    let res;
    let next;
    let save;
    beforeEach(() => {
        res = { sendFile: sinon_1.default.spy(), status: sinon_1.default.spy() };
        req = { params: {}, query: {} };
        next = sinon_1.default.spy();
        save = () => ({
            then() { }
        });
    });
    it('should serve PDF files from folder /ftp', () => {
        req.params.file = 'test.pdf';
        (0, fileServer_1.servePublicFiles)()(req, res, next);
        expect(res.sendFile).to.have.been.calledWith(sinon_1.default.match(/ftp[/\\]test\.pdf/));
    });
    it('should serve Markdown files from folder /ftp', () => {
        req.params.file = 'test.md';
        (0, fileServer_1.servePublicFiles)()(req, res, next);
        expect(res.sendFile).to.have.been.calledWith(sinon_1.default.match(/ftp[/\\]test\.md/));
    });
    it('should serve incident-support.kdbx files from folder /ftp', () => {
        req.params.file = 'incident-support.kdbx';
        (0, fileServer_1.servePublicFiles)()(req, res, next);
        expect(res.sendFile).to.have.been.calledWith(sinon_1.default.match(/ftp[/\\]incident-support\.kdbx/));
    });
    it('should raise error for slashes in filename', () => {
        req.params.file = '../../../../nice.try';
        (0, fileServer_1.servePublicFiles)()(req, res, next);
        expect(res.sendFile).to.have.not.been.calledWith(sinon_1.default.match.any);
        expect(next).to.have.been.calledWith(sinon_1.default.match.instanceOf(Error));
    });
    it('should raise error for disallowed file type', () => {
        req.params.file = 'nice.try';
        (0, fileServer_1.servePublicFiles)()(req, res, next);
        expect(res.sendFile).to.have.not.been.calledWith(sinon_1.default.match.any);
        expect(next).to.have.been.calledWith(sinon_1.default.match.instanceOf(Error));
    });
    it('should solve "directoryListingChallenge" when requesting acquisitions.md', () => {
        datacache_1.challenges.directoryListingChallenge = { solved: false, save };
        req.params.file = 'acquisitions.md';
        (0, fileServer_1.servePublicFiles)()(req, res, next);
        expect(res.sendFile).to.have.been.calledWith(sinon_1.default.match(/ftp[/\\]acquisitions\.md/));
        expect(datacache_1.challenges.directoryListingChallenge.solved).to.equal(true);
    });
    it('should solve "easterEggLevelOneChallenge" when requesting eastere.gg with Poison Null Byte attack', () => {
        datacache_1.challenges.easterEggLevelOneChallenge = { solved: false, save };
        req.params.file = 'eastere.gg%00.md';
        (0, fileServer_1.servePublicFiles)()(req, res, next);
        expect(res.sendFile).to.have.been.calledWith(sinon_1.default.match(/ftp[/\\]eastere\.gg/));
        expect(datacache_1.challenges.easterEggLevelOneChallenge.solved).to.equal(true);
    });
    it('should solve "forgottenDevBackupChallenge" when requesting package.json.bak with Poison Null Byte attack', () => {
        datacache_1.challenges.forgottenDevBackupChallenge = { solved: false, save };
        req.params.file = 'package.json.bak%00.md';
        (0, fileServer_1.servePublicFiles)()(req, res, next);
        expect(res.sendFile).to.have.been.calledWith(sinon_1.default.match(/ftp[/\\]package\.json\.bak/));
        expect(datacache_1.challenges.forgottenDevBackupChallenge.solved).to.equal(true);
    });
    it('should solve "forgottenBackupChallenge" when requesting coupons_2013.md.bak with Poison Null Byte attack', () => {
        datacache_1.challenges.forgottenBackupChallenge = { solved: false, save };
        req.params.file = 'coupons_2013.md.bak%00.md';
        (0, fileServer_1.servePublicFiles)()(req, res, next);
        expect(res.sendFile).to.have.been.calledWith(sinon_1.default.match(/ftp[/\\]coupons_2013\.md\.bak/));
        expect(datacache_1.challenges.forgottenBackupChallenge.solved).to.equal(true);
    });
    it('should solve "misplacedSignatureFileChallenge" when requesting suspicious_errors.yml with Poison Null Byte attack', () => {
        datacache_1.challenges.misplacedSignatureFileChallenge = { solved: false, save };
        req.params.file = 'suspicious_errors.yml%00.md';
        (0, fileServer_1.servePublicFiles)()(req, res, next);
        expect(res.sendFile).to.have.been.calledWith(sinon_1.default.match(/ftp[/\\]suspicious_errors\.yml/));
        expect(datacache_1.challenges.misplacedSignatureFileChallenge.solved).to.equal(true);
    });
});
//# sourceMappingURL=fileServerSpec.js.map