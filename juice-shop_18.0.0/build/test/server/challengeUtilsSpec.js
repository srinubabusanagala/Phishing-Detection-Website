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
const challengeUtils = __importStar(require("../../lib/challengeUtils"));
const datacache_1 = require("../../data/datacache");
const expect = chai_1.default.expect;
describe('challengeUtils', () => {
    beforeEach(() => {
        datacache_1.challenges.scoreBoardChallenge = { id: 42, name: 'scoreBoardChallenge' };
    });
    describe('findChallengeByName', () => {
        it('returns undefined for non-existing challenge', () => {
            expect(challengeUtils.findChallengeByName('blubbChallenge')).to.equal(undefined);
        });
        it('returns existing challenge', () => {
            expect(challengeUtils.findChallengeByName('scoreBoardChallenge')).to.deep.equal({ id: 42, name: 'scoreBoardChallenge' });
        });
    });
    describe('findChallengeById', () => {
        it('returns undefined for non-existing challenge', () => {
            expect(challengeUtils.findChallengeById(43)).to.equal(undefined);
        });
        it('returns existing challenge', () => {
            expect(challengeUtils.findChallengeById(42)).to.deep.equal({ id: 42, name: 'scoreBoardChallenge' });
        });
    });
});
//# sourceMappingURL=challengeUtilsSpec.js.map