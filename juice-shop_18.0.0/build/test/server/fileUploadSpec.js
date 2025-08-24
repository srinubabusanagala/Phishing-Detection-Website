"use strict";
/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const chai_1 = __importDefault(require("chai"));
const datacache_1 = require("../../data/datacache");
const fileUpload_1 = require("../../routes/fileUpload");
const expect = chai_1.default.expect;
describe('fileUpload', () => {
    let req;
    let res;
    let save;
    beforeEach(() => {
        req = { file: { originalname: '' } };
        res = {};
        save = () => ({
            then() { }
        });
    });
    describe('should not solve "uploadSizeChallenge" when file size is', () => {
        const sizes = [0, 1, 100, 1000, 10000, 99999, 100000];
        sizes.forEach(size => {
            it(`${size} bytes`, () => {
                datacache_1.challenges.uploadSizeChallenge = { solved: false, save };
                req.file.size = size;
                (0, fileUpload_1.checkUploadSize)(req, res, () => { });
                expect(datacache_1.challenges.uploadSizeChallenge.solved).to.equal(false);
            });
        });
    });
    it('should solve "uploadSizeChallenge" when file size exceeds 100000 bytes', () => {
        datacache_1.challenges.uploadSizeChallenge = { solved: false, save };
        req.file.size = 100001;
        (0, fileUpload_1.checkUploadSize)(req, res, () => { });
        expect(datacache_1.challenges.uploadSizeChallenge.solved).to.equal(true);
    });
    it('should solve "uploadTypeChallenge" when file type is not PDF', () => {
        datacache_1.challenges.uploadTypeChallenge = { solved: false, save };
        req.file.originalname = 'hack.exe';
        (0, fileUpload_1.checkFileType)(req, res, () => { });
        expect(datacache_1.challenges.uploadTypeChallenge.solved).to.equal(true);
    });
    it('should not solve "uploadTypeChallenge" when file type is PDF', () => {
        datacache_1.challenges.uploadTypeChallenge = { solved: false, save };
        req.file.originalname = 'hack.pdf';
        (0, fileUpload_1.checkFileType)(req, res, () => { });
        expect(datacache_1.challenges.uploadTypeChallenge.solved).to.equal(false);
    });
});
//# sourceMappingURL=fileUploadSpec.js.map