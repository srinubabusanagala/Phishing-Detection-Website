"use strict";
/*
 * Copyright (c) 2014-2021 Bjoern Kimminich.
 * SPDX-License-Identifier: MIT
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getFindItAttempts = exports.totalFixItAccuracy = exports.totalFindItAccuracy = exports.calculateFixItAccuracy = exports.calculateFindItAccuracy = exports.storeFixItVerdict = exports.storeFindItVerdict = void 0;
const logger_1 = __importDefault(require("./logger"));
const safe_1 = __importDefault(require("colors/safe"));
const solves = {};
const storeFindItVerdict = (challengeKey, verdict) => {
    storeVerdict(challengeKey, 'find it', verdict);
};
exports.storeFindItVerdict = storeFindItVerdict;
const storeFixItVerdict = (challengeKey, verdict) => {
    storeVerdict(challengeKey, 'fix it', verdict);
};
exports.storeFixItVerdict = storeFixItVerdict;
const calculateFindItAccuracy = (challengeKey) => {
    return calculateAccuracy(challengeKey, 'find it');
};
exports.calculateFindItAccuracy = calculateFindItAccuracy;
const calculateFixItAccuracy = (challengeKey) => {
    return calculateAccuracy(challengeKey, 'fix it');
};
exports.calculateFixItAccuracy = calculateFixItAccuracy;
const totalFindItAccuracy = () => {
    return totalAccuracy('find it');
};
exports.totalFindItAccuracy = totalFindItAccuracy;
const totalFixItAccuracy = () => {
    return totalAccuracy('fix it');
};
exports.totalFixItAccuracy = totalFixItAccuracy;
const getFindItAttempts = (challengeKey) => {
    return solves[challengeKey] ? solves[challengeKey].attempts['find it'] : 0;
};
exports.getFindItAttempts = getFindItAttempts;
function totalAccuracy(phase) {
    let sumAccuracy = 0;
    let totalSolved = 0;
    Object.entries(solves).forEach(([key, value]) => {
        if (value[phase]) {
            sumAccuracy += 1 / value.attempts[phase];
            totalSolved++;
        }
    });
    return sumAccuracy / totalSolved;
}
function calculateAccuracy(challengeKey, phase) {
    let accuracy = 0;
    if (solves[challengeKey][phase]) {
        accuracy = 1 / solves[challengeKey].attempts[phase];
    }
    logger_1.default.info(`Accuracy for '${phase === 'fix it' ? 'Fix It' : 'Find It'}' phase of coding challenge ${safe_1.default.cyan(challengeKey)}: ${accuracy > 0.5 ? safe_1.default.green(accuracy.toString()) : (accuracy > 0.25 ? safe_1.default.yellow(accuracy.toString()) : safe_1.default.red(accuracy.toString()))}`);
    return accuracy;
}
function storeVerdict(challengeKey, phase, verdict) {
    if (!solves[challengeKey]) {
        solves[challengeKey] = { 'find it': false, 'fix it': false, attempts: { 'find it': 0, 'fix it': 0 } };
    }
    if (!solves[challengeKey][phase]) {
        solves[challengeKey][phase] = verdict;
        solves[challengeKey].attempts[phase]++;
    }
}
//# sourceMappingURL=accuracy.js.map