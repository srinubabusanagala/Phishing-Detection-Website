"use strict";
/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const chai_1 = __importDefault(require("chai"));
const sinon_1 = __importDefault(require("sinon"));
const config_1 = __importDefault(require("config"));
const sinon_chai_1 = __importDefault(require("sinon-chai"));
const datacache_1 = require("../../data/datacache");
const security = __importStar(require("../../lib/insecurity"));
const utils = __importStar(require("../../lib/utils"));
const verify = __importStar(require("../../routes/verify"));
const expect = chai_1.default.expect;
chai_1.default.use(sinon_chai_1.default);
describe('verify', () => {
    let req;
    let res;
    let next;
    let save;
    let err;
    beforeEach(() => {
        req = { body: {}, headers: {} };
        res = { json: sinon_1.default.spy() };
        next = sinon_1.default.spy();
        save = () => ({
            then() { }
        });
    });
    describe('"forgedFeedbackChallenge"', () => {
        beforeEach(() => {
            security.authenticatedUsers.put('token12345', {
                data: {
                    id: 42,
                    email: 'test@juice-sh.op'
                }
            });
            datacache_1.challenges.forgedFeedbackChallenge = { solved: false, save };
        });
        it('is not solved when an authenticated user passes his own ID when writing feedback', () => {
            req.body.UserId = 42;
            req.headers = { authorization: 'Bearer token12345' };
            verify.forgedFeedbackChallenge()(req, res, next);
            expect(datacache_1.challenges.forgedFeedbackChallenge.solved).to.equal(false);
        });
        it('is not solved when an authenticated user passes no ID when writing feedback', () => {
            req.body.UserId = undefined;
            req.headers = { authorization: 'Bearer token12345' };
            verify.forgedFeedbackChallenge()(req, res, next);
            expect(datacache_1.challenges.forgedFeedbackChallenge.solved).to.equal(false);
        });
        it('is solved when an authenticated user passes someone elses ID when writing feedback', () => {
            req.body.UserId = 1;
            req.headers = { authorization: 'Bearer token12345' };
            verify.forgedFeedbackChallenge()(req, res, next);
            expect(datacache_1.challenges.forgedFeedbackChallenge.solved).to.equal(true);
        });
        it('is solved when an unauthenticated user passes someones ID when writing feedback', () => {
            req.body.UserId = 1;
            req.headers = {};
            verify.forgedFeedbackChallenge()(req, res, next);
            expect(datacache_1.challenges.forgedFeedbackChallenge.solved).to.equal(true);
        });
    });
    describe('accessControlChallenges', () => {
        it('"scoreBoardChallenge" is solved when the 1px.png transpixel is requested', () => {
            datacache_1.challenges.scoreBoardChallenge = { solved: false, save };
            req.url = 'http://juice-sh.op/public/images/padding/1px.png';
            verify.accessControlChallenges()(req, res, next);
            expect(datacache_1.challenges.scoreBoardChallenge.solved).to.equal(true);
        });
        it('"adminSectionChallenge" is solved when the 19px.png transpixel is requested', () => {
            datacache_1.challenges.adminSectionChallenge = { solved: false, save };
            req.url = 'http://juice-sh.op/public/images/padding/19px.png';
            verify.accessControlChallenges()(req, res, next);
            expect(datacache_1.challenges.adminSectionChallenge.solved).to.equal(true);
        });
        it('"tokenSaleChallenge" is solved when the 56px.png transpixel is requested', () => {
            datacache_1.challenges.tokenSaleChallenge = { solved: false, save };
            req.url = 'http://juice-sh.op/public/images/padding/56px.png';
            verify.accessControlChallenges()(req, res, next);
            expect(datacache_1.challenges.tokenSaleChallenge.solved).to.equal(true);
        });
        it('"extraLanguageChallenge" is solved when the Klingon translation file is requested', () => {
            datacache_1.challenges.extraLanguageChallenge = { solved: false, save };
            req.url = 'http://juice-sh.op/public/i18n/tlh_AA.json';
            verify.accessControlChallenges()(req, res, next);
            expect(datacache_1.challenges.extraLanguageChallenge.solved).to.equal(true);
        });
        it('"retrieveBlueprintChallenge" is solved when the blueprint file is requested', () => {
            datacache_1.challenges.retrieveBlueprintChallenge = { solved: false, save };
            (0, datacache_1.setRetrieveBlueprintChallengeFile)('test.dxf');
            req.url = 'http://juice-sh.op/public/images/products/test.dxf';
            verify.accessControlChallenges()(req, res, next);
            expect(datacache_1.challenges.retrieveBlueprintChallenge.solved).to.equal(true);
        });
        it('"missingEncodingChallenge" is solved when the crazy cat photo is requested', () => {
            datacache_1.challenges.missingEncodingChallenge = { solved: false, save };
            req.url = 'http://juice-sh.op/public/images/uploads/%E1%93%9A%E1%98%8F%E1%97%A2-%23zatschi-%23whoneedsfourlegs-1572600969477.jpg';
            verify.accessControlChallenges()(req, res, next);
            expect(datacache_1.challenges.missingEncodingChallenge.solved).to.equal(true);
        });
        it('"accessLogDisclosureChallenge" is solved when any server access log file is requested', () => {
            datacache_1.challenges.accessLogDisclosureChallenge = { solved: false, save };
            req.url = 'http://juice-sh.op/support/logs/access.log.2019-01-15';
            verify.accessControlChallenges()(req, res, next);
            expect(datacache_1.challenges.accessLogDisclosureChallenge.solved).to.equal(true);
        });
    });
    describe('"errorHandlingChallenge"', () => {
        beforeEach(() => {
            datacache_1.challenges.errorHandlingChallenge = { solved: false, save };
        });
        it('is solved when an error occurs on a response with OK 200 status code', () => {
            res.statusCode = 200;
            err = new Error();
            verify.errorHandlingChallenge()(err, req, res, next);
            expect(datacache_1.challenges.errorHandlingChallenge.solved).to.equal(true);
        });
        describe('is solved when an error occurs on a response with error', () => {
            const httpStatus = [402, 403, 404, 500];
            httpStatus.forEach(statusCode => {
                it(`${statusCode} status code`, () => {
                    res.statusCode = statusCode;
                    err = new Error();
                    verify.errorHandlingChallenge()(err, req, res, next);
                    expect(datacache_1.challenges.errorHandlingChallenge.solved).to.equal(true);
                });
            });
        });
        it('is not solved when no error occurs on a response with OK 200 status code', () => {
            res.statusCode = 200;
            err = undefined;
            verify.errorHandlingChallenge()(err, req, res, next);
            expect(datacache_1.challenges.errorHandlingChallenge.solved).to.equal(false);
        });
        describe('is not solved when no error occurs on a response with error', () => {
            const httpStatus = [401, 402, 404, 500];
            httpStatus.forEach(statusCode => {
                it(`${statusCode} status code`, () => {
                    res.statusCode = statusCode;
                    err = undefined;
                    verify.errorHandlingChallenge()(err, req, res, next);
                    expect(datacache_1.challenges.errorHandlingChallenge.solved).to.equal(false);
                });
            });
        });
        it('should pass occurred error on to next route', () => {
            res.statusCode = 500;
            err = new Error();
            verify.errorHandlingChallenge()(err, req, res, next);
            expect(next).to.have.been.calledWith(err);
        });
    });
    describe('databaseRelatedChallenges', () => {
        describe('"changeProductChallenge"', () => {
            beforeEach(() => {
                datacache_1.challenges.changeProductChallenge = { solved: false, save };
                datacache_1.products.osaft = { reload() { return { then(cb) { cb(); } }; } };
            });
            it(`is solved when the link in the O-Saft product goes to ${config_1.default.get('challenges.overwriteUrlForProductTamperingChallenge')}`, () => {
                datacache_1.products.osaft.description = `O-Saft, yeah! <a href="${config_1.default.get('challenges.overwriteUrlForProductTamperingChallenge')}" target="_blank">More...</a>`;
                verify.databaseRelatedChallenges()(req, res, next);
                expect(datacache_1.challenges.changeProductChallenge.solved).to.equal(true);
            });
            it('is not solved when the link in the O-Saft product is changed to an arbitrary URL', () => {
                datacache_1.products.osaft.description = 'O-Saft, nooo! <a href="http://arbitrary.url" target="_blank">More...</a>';
                verify.databaseRelatedChallenges()(req, res, next);
                expect(datacache_1.challenges.changeProductChallenge.solved).to.equal(false);
            });
            it('is not solved when the link in the O-Saft product remained unchanged', () => {
                let urlForProductTamperingChallenge = null;
                for (const product of config_1.default.get('products')) {
                    if (product.urlForProductTamperingChallenge !== undefined) {
                        urlForProductTamperingChallenge = product.urlForProductTamperingChallenge;
                        break;
                    }
                }
                datacache_1.products.osaft.description = `Vanilla O-Saft! <a href="${urlForProductTamperingChallenge}" target="_blank">More...</a>`;
                verify.databaseRelatedChallenges()(req, res, next);
                expect(datacache_1.challenges.changeProductChallenge.solved).to.equal(false);
            });
        });
    });
    describe('jwtChallenges', () => {
        beforeEach(() => {
            datacache_1.challenges.jwtUnsignedChallenge = { solved: false, save };
            datacache_1.challenges.jwtForgedChallenge = { solved: false, save };
        });
        it('"jwtUnsignedChallenge" is solved when forged unsigned token has email jwtn3d@juice-sh.op in the payload', () => {
            /*
            Header: { "alg": "none", "typ": "JWT" }
            Payload: { "data": { "email": "jwtn3d@juice-sh.op" }, "iat": 1508639612, "exp": 9999999999 }
             */
            req.headers = { authorization: 'Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJkYXRhIjp7ImVtYWlsIjoiand0bjNkQGp1aWNlLXNoLm9wIn0sImlhdCI6MTUwODYzOTYxMiwiZXhwIjo5OTk5OTk5OTk5fQ.' };
            verify.jwtChallenges()(req, res, next);
            expect(datacache_1.challenges.jwtUnsignedChallenge.solved).to.equal(true);
        });
        it('"jwtUnsignedChallenge" is solved when forged unsigned token has string "jwtn3d@" in the payload', () => {
            /*
            Header: { "alg": "none", "typ": "JWT" }
            Payload: { "data": { "email": "jwtn3d@" }, "iat": 1508639612, "exp": 9999999999 }
             */
            req.headers = { authorization: 'Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJkYXRhIjp7ImVtYWlsIjoiand0bjNkQCJ9LCJpYXQiOjE1MDg2Mzk2MTIsImV4cCI6OTk5OTk5OTk5OX0.' };
            verify.jwtChallenges()(req, res, next);
            expect(datacache_1.challenges.jwtUnsignedChallenge.solved).to.equal(true);
        });
        it('"jwtUnsignedChallenge" is not solved via regularly signed token even with email jwtn3d@juice-sh.op in the payload', () => {
            const token = security.authorize({ data: { email: 'jwtn3d@juice-sh.op' } });
            req.headers = { authorization: `Bearer ${token}` };
            verify.jwtChallenges()(req, res, next);
            expect(datacache_1.challenges.jwtForgedChallenge.solved).to.equal(false);
        });
        if (utils.isChallengeEnabled(datacache_1.challenges.jwtForgedChallenge)) {
            it('"jwtForgedChallenge" is solved when forged token HMAC-signed with public RSA-key has email rsa_lord@juice-sh.op in the payload', () => {
                /*
                Header: { "alg": "HS256", "typ": "JWT" }
                Payload: { "data": { "email": "rsa_lord@juice-sh.op" }, "iat": 1508639612, "exp": 9999999999 }
                 */
                req.headers = { authorization: 'Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjp7ImVtYWlsIjoicnNhX2xvcmRAanVpY2Utc2gub3AifSwiaWF0IjoxNTgyMjIxNTc1fQ.ycFwtqh4ht4Pq9K5rhiPPY256F9YCTIecd4FHFuSEAg' };
                verify.jwtChallenges()(req, res, next);
                expect(datacache_1.challenges.jwtForgedChallenge.solved).to.equal(true);
            });
            it('"jwtForgedChallenge" is solved when forged token HMAC-signed with public RSA-key has string "rsa_lord@" in the payload', () => {
                /*
                Header: { "alg": "HS256", "typ": "JWT" }
                Payload: { "data": { "email": "rsa_lord@" }, "iat": 1508639612, "exp": 9999999999 }
                 */
                req.headers = { authorization: 'Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjp7ImVtYWlsIjoicnNhX2xvcmRAIn0sImlhdCI6MTU4MjIyMTY3NX0.50f6VAIQk2Uzpf3sgH-1JVrrTuwudonm2DKn2ec7Tg8' };
                verify.jwtChallenges()(req, res, next);
                expect(datacache_1.challenges.jwtForgedChallenge.solved).to.equal(true);
            });
            it('"jwtForgedChallenge" is not solved when token regularly signed with private RSA-key has email rsa_lord@juice-sh.op in the payload', () => {
                const token = security.authorize({ data: { email: 'rsa_lord@juice-sh.op' } });
                req.headers = { authorization: `Bearer ${token}` };
                verify.jwtChallenges()(req, res, next);
                expect(datacache_1.challenges.jwtForgedChallenge.solved).to.equal(false);
            });
        }
    });
});
//# sourceMappingURL=verifySpec.js.map