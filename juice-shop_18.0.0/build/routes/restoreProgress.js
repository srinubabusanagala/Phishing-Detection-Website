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
exports.restoreProgressFixIt = exports.restoreProgressFindIt = exports.restoreProgress = void 0;
const cjs_1 = __importDefault(require("hashids/cjs"));
const challengeUtils = __importStar(require("../lib/challengeUtils"));
const datacache_1 = require("../data/datacache");
const hashidsAlphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890';
const hashidRegexp = /^[a-zA-Z0-9]+$/;
const invalidContinueCode = 'Invalid continue code.';
function restoreProgress() {
    return ({ params }, res) => {
        const hashids = new cjs_1.default('this is my salt', 60, hashidsAlphabet);
        const continueCode = params.continueCode;
        if (!hashidRegexp.test(continueCode)) {
            return res.status(404).send(invalidContinueCode);
        }
        const ids = hashids.decode(continueCode);
        if (challengeUtils.notSolved(datacache_1.challenges.continueCodeChallenge) && ids.includes(999)) {
            challengeUtils.solve(datacache_1.challenges.continueCodeChallenge);
            res.end();
        }
        else if (ids.length > 0) {
            for (const challenge of Object.values(datacache_1.challenges)) {
                if (ids.includes(challenge.id)) {
                    challengeUtils.solve(challenge, true);
                }
            }
            res.json({ data: ids.length + ' solved challenges have been restored.' });
        }
        else {
            res.status(404).send(invalidContinueCode);
        }
    };
}
exports.restoreProgress = restoreProgress;
function restoreProgressFindIt() {
    return async ({ params }, res) => {
        const hashids = new cjs_1.default('this is the salt for findIt challenges', 60, hashidsAlphabet);
        const continueCodeFindIt = params.continueCode;
        if (!hashidRegexp.test(continueCodeFindIt)) {
            return res.status(404).send(invalidContinueCode);
        }
        const idsFindIt = hashids.decode(continueCodeFindIt);
        if (idsFindIt.length > 0) {
            for (const challenge of Object.values(datacache_1.challenges)) {
                if (idsFindIt.includes(challenge.id)) {
                    await challengeUtils.solveFindIt(challenge.key, true);
                }
            }
            res.json({ data: idsFindIt.length + ' solved challenges have been restored.' });
        }
        else {
            res.status(404).send(invalidContinueCode);
        }
    };
}
exports.restoreProgressFindIt = restoreProgressFindIt;
function restoreProgressFixIt() {
    const hashids = new cjs_1.default('yet another salt for the fixIt challenges', 60, hashidsAlphabet);
    return async ({ params }, res) => {
        const continueCodeFixIt = params.continueCode;
        if (!hashidRegexp.test(continueCodeFixIt)) {
            return res.status(404).send(invalidContinueCode);
        }
        const idsFixIt = hashids.decode(continueCodeFixIt);
        if (idsFixIt.length > 0) {
            for (const challenge of Object.values(datacache_1.challenges)) {
                if (idsFixIt.includes(challenge.id)) {
                    await challengeUtils.solveFixIt(challenge.key, true);
                }
            }
            res.json({ data: idsFixIt.length + ' solved challenges have been restored.' });
        }
        else {
            res.status(404).send(invalidContinueCode);
        }
    };
}
exports.restoreProgressFixIt = restoreProgressFixIt;
//# sourceMappingURL=restoreProgress.js.map