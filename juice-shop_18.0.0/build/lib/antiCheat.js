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
exports.totalCheatScore = exports.calculateFixItCheatScore = exports.calculateFindItCheatScore = exports.calculateCheatScore = exports.checkForPreSolveInteractions = void 0;
const config_1 = __importDefault(require("config"));
const safe_1 = __importDefault(require("colors/safe"));
const vulnCodeSnippet_1 = require("../routes/vulnCodeSnippet");
const vulnCodeFixes_1 = require("../routes/vulnCodeFixes");
const codingChallenges_1 = require("./codingChallenges");
const logger_1 = __importDefault(require("./logger"));
const utils = __importStar(require("./utils"));
// @ts-expect-error FIXME due to non-existing type definitions for median
const median_1 = __importDefault(require("median"));
const coupledChallenges = {
    loginAdminChallenge: ['weakPasswordChallenge'],
    nullByteChallenge: ['easterEggLevelOneChallenge', 'forgottenDevBackupChallenge', 'forgottenBackupChallenge', 'misplacedSignatureFileChallenge'],
    deprecatedInterfaceChallenge: ['uploadTypeChallenge', 'xxeFileDisclosureChallenge', 'xxeDosChallenge', 'yamlBombChallenge'],
    uploadSizeChallenge: ['uploadTypeChallenge', 'xxeFileDisclosureChallenge', 'xxeDosChallenge', 'yamlBombChallenge'],
    uploadTypeChallenge: ['uploadSizeChallenge', 'xxeFileDisclosureChallenge', 'xxeDosChallenge', 'yamlBombChallenge']
};
const trivialChallenges = ['errorHandlingChallenge', 'privacyPolicyChallenge', 'closeNotificationsChallenge'];
const solves = [{ challenge: {}, phase: 'server start', timestamp: new Date(), cheatScore: 0 }]; // seed with server start timestamp
const preSolveInteractions = [
    { challengeKey: 'missingEncodingChallenge', urlFragments: ['/assets/public/images/uploads/%F0%9F%98%BC-'], interactions: [false] },
    { challengeKey: 'directoryListingChallenge', urlFragments: ['/ftp'], interactions: [false] },
    { challengeKey: 'easterEggLevelOneChallenge', urlFragments: ['/ftp', '/ftp/eastere.gg'], interactions: [false, false] },
    { challengeKey: 'easterEggLevelTwoChallenge', urlFragments: ['/ftp', '/gur/qrif/ner/fb/shaal/gurl/uvq/na/rnfgre/rtt/jvguva/gur/rnfgre/rtt'], interactions: [false, false] },
    { challengeKey: 'forgottenDevBackupChallenge', urlFragments: ['/ftp', '/ftp/package.json.bak'], interactions: [false, false] },
    { challengeKey: 'forgottenBackupChallenge', urlFragments: ['/ftp', '/ftp/coupons_2013.md.bak'], interactions: [false, false] },
    { challengeKey: 'loginSupportChallenge', urlFragments: ['/ftp', '/ftp/incident-support.kdbx'], interactions: [false, false] },
    { challengeKey: 'misplacedSignatureFileChallenge', urlFragments: ['/ftp', '/ftp/suspicious_errors.yml'], interactions: [false, false] },
    { challengeKey: 'rceChallenge', urlFragments: ['/api-docs', '/b2b/v2/orders'], interactions: [false, false] },
    { challengeKey: 'rceOccupyChallenge', urlFragments: ['/api-docs', '/b2b/v2/orders'], interactions: [false, false] }
];
const checkForPreSolveInteractions = () => ({ url }, res, next) => {
    preSolveInteractions.forEach((preSolveInteraction) => {
        for (let i = 0; i < preSolveInteraction.urlFragments.length; i++) {
            if (utils.endsWith(url, preSolveInteraction.urlFragments[i])) {
                preSolveInteraction.interactions[i] = true;
            }
        }
    });
    next();
};
exports.checkForPreSolveInteractions = checkForPreSolveInteractions;
const calculateCheatScore = (challenge) => {
    const timestamp = new Date();
    let cheatScore = 0;
    let timeFactor = 2;
    timeFactor *= (config_1.default.get('challenges.showHints') ? 1 : 1.5);
    timeFactor *= (challenge.tutorialOrder && config_1.default.get('hackingInstructor.isEnabled') ? 0.5 : 1);
    if (areCoupled(challenge, previous().challenge) || isTrivial(challenge)) {
        timeFactor = 0;
    }
    const minutesExpectedToSolve = challenge.difficulty * timeFactor;
    const minutesSincePreviousSolve = (timestamp.getTime() - previous().timestamp.getTime()) / 60000;
    cheatScore += Math.max(0, 1 - (minutesSincePreviousSolve / minutesExpectedToSolve));
    const preSolveInteraction = preSolveInteractions.find((preSolveInteraction) => preSolveInteraction.challengeKey === challenge.key);
    let percentPrecedingInteraction = -1;
    if (preSolveInteraction) {
        percentPrecedingInteraction = preSolveInteraction.interactions.filter(Boolean).length / (preSolveInteraction.interactions.length);
        const multiplierForMissingExpectedInteraction = 1 + Math.max(0, 1 - percentPrecedingInteraction) / 2;
        cheatScore *= multiplierForMissingExpectedInteraction;
        cheatScore = Math.min(1, cheatScore);
    }
    logger_1.default.info(`Cheat score for ${areCoupled(challenge, previous().challenge) ? 'coupled ' : (isTrivial(challenge) ? 'trivial ' : '')}${challenge.tutorialOrder ? 'tutorial ' : ''}${safe_1.default.cyan(challenge.key)} solved in ${Math.round(minutesSincePreviousSolve)}min (expected ~${minutesExpectedToSolve}min) with${config_1.default.get('challenges.showHints') ? '' : 'out'} hints allowed${percentPrecedingInteraction > -1 ? (' and ' + percentPrecedingInteraction * 100 + '% expected preceding URL interaction') : ''}: ${cheatScore < 0.33 ? safe_1.default.green(cheatScore.toString()) : (cheatScore < 0.66 ? safe_1.default.yellow(cheatScore.toString()) : safe_1.default.red(cheatScore.toString()))}`);
    solves.push({ challenge, phase: 'hack it', timestamp, cheatScore });
    return cheatScore;
};
exports.calculateCheatScore = calculateCheatScore;
const calculateFindItCheatScore = async (challenge) => {
    const timestamp = new Date();
    let timeFactor = 0.001;
    timeFactor *= (challenge.key === 'scoreBoardChallenge' && config_1.default.get('hackingInstructor.isEnabled') ? 0.5 : 1);
    let cheatScore = 0;
    const codeSnippet = await (0, vulnCodeSnippet_1.retrieveCodeSnippet)(challenge.key);
    if (codeSnippet == null) {
        return 0;
    }
    const { snippet, vulnLines } = codeSnippet;
    timeFactor *= vulnLines.length;
    const identicalSolved = await checkForIdenticalSolvedChallenge(challenge);
    if (identicalSolved) {
        timeFactor = 0.8 * timeFactor;
    }
    const minutesExpectedToSolve = Math.ceil(snippet.length * timeFactor);
    const minutesSincePreviousSolve = (timestamp.getTime() - previous().timestamp.getTime()) / 60000;
    cheatScore += Math.max(0, 1 - (minutesSincePreviousSolve / minutesExpectedToSolve));
    logger_1.default.info(`Cheat score for "Find it" phase of ${challenge.key === 'scoreBoardChallenge' && config_1.default.get('hackingInstructor.isEnabled') ? 'tutorial ' : ''}${safe_1.default.cyan(challenge.key)} solved in ${Math.round(minutesSincePreviousSolve)}min (expected ~${minutesExpectedToSolve}min): ${cheatScore < 0.33 ? safe_1.default.green(cheatScore.toString()) : (cheatScore < 0.66 ? safe_1.default.yellow(cheatScore.toString()) : safe_1.default.red(cheatScore.toString()))}`);
    solves.push({ challenge, phase: 'find it', timestamp, cheatScore });
    return cheatScore;
};
exports.calculateFindItCheatScore = calculateFindItCheatScore;
const calculateFixItCheatScore = async (challenge) => {
    const timestamp = new Date();
    let cheatScore = 0;
    const { fixes } = (0, vulnCodeFixes_1.readFixes)(challenge.key);
    const minutesExpectedToSolve = Math.floor(fixes.length / 2);
    const minutesSincePreviousSolve = (timestamp.getTime() - previous().timestamp.getTime()) / 60000;
    cheatScore += Math.max(0, 1 - (minutesSincePreviousSolve / minutesExpectedToSolve));
    logger_1.default.info(`Cheat score for "Fix it" phase of ${safe_1.default.cyan(challenge.key)} solved in ${Math.round(minutesSincePreviousSolve)}min (expected ~${minutesExpectedToSolve}min): ${cheatScore < 0.33 ? safe_1.default.green(cheatScore.toString()) : (cheatScore < 0.66 ? safe_1.default.yellow(cheatScore.toString()) : safe_1.default.red(cheatScore.toString()))}`);
    solves.push({ challenge, phase: 'fix it', timestamp, cheatScore });
    return cheatScore;
};
exports.calculateFixItCheatScore = calculateFixItCheatScore;
const totalCheatScore = () => {
    return solves.length > 1 ? (0, median_1.default)(solves.map(({ cheatScore }) => cheatScore)) : 0;
};
exports.totalCheatScore = totalCheatScore;
function areCoupled(challenge, previousChallenge) {
    // @ts-expect-error FIXME any type issues
    return coupledChallenges[challenge.key]?.indexOf(previousChallenge.key) > -1 || coupledChallenges[previousChallenge.key]?.indexOf(challenge.key) > -1;
}
function isTrivial(challenge) {
    return trivialChallenges.includes(challenge.key);
}
function previous() {
    return solves[solves.length - 1];
}
const checkForIdenticalSolvedChallenge = async (challenge) => {
    const codingChallenges = await (0, codingChallenges_1.getCodeChallenges)();
    if (!codingChallenges.has(challenge.key)) {
        return false;
    }
    const codingChallengesToCompareTo = codingChallenges.get(challenge.key);
    if (!codingChallengesToCompareTo?.snippet) {
        return false;
    }
    const snippetToCompareTo = codingChallengesToCompareTo.snippet;
    for (const [challengeKey, { snippet }] of codingChallenges.entries()) {
        if (challengeKey === challenge.key) {
            // don't compare to itself
            continue;
        }
        if (snippet === snippetToCompareTo) {
            for (const solvedChallenges of solves) {
                if (solvedChallenges.phase === 'find it') {
                    return true;
                }
            }
        }
    }
    return false;
};
//# sourceMappingURL=antiCheat.js.map