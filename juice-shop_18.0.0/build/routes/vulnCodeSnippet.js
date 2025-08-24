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
exports.checkVulnLines = exports.getVerdict = exports.retrieveChallengesWithCodeSnippet = exports.serveCodeSnippet = exports.retrieveCodeSnippet = void 0;
const js_yaml_1 = __importDefault(require("js-yaml"));
const node_fs_1 = __importDefault(require("node:fs"));
const codingChallenges_1 = require("../lib/codingChallenges");
const challengeUtils = __importStar(require("../lib/challengeUtils"));
const accuracy = __importStar(require("../lib/accuracy"));
const utils = __importStar(require("../lib/utils"));
const setStatusCode = (error) => {
    switch (error.name) {
        case 'BrokenBoundary':
            return 422;
        default:
            return 200;
    }
};
const retrieveCodeSnippet = async (challengeKey) => {
    const codeChallenges = await (0, codingChallenges_1.getCodeChallenges)();
    if (codeChallenges.has(challengeKey)) {
        return codeChallenges.get(challengeKey) ?? null;
    }
    return null;
};
exports.retrieveCodeSnippet = retrieveCodeSnippet;
const serveCodeSnippet = () => async (req, res, next) => {
    try {
        const snippetData = await (0, exports.retrieveCodeSnippet)(req.params.challenge);
        if (snippetData == null) {
            res.status(404).json({ status: 'error', error: `No code challenge for challenge key: ${req.params.challenge}` });
            return;
        }
        res.status(200).json({ snippet: snippetData.snippet });
    }
    catch (error) {
        const statusCode = setStatusCode(error);
        res.status(statusCode).json({ status: 'error', error: utils.getErrorMessage(error) });
    }
};
exports.serveCodeSnippet = serveCodeSnippet;
const retrieveChallengesWithCodeSnippet = async () => {
    const codeChallenges = await (0, codingChallenges_1.getCodeChallenges)();
    return [...codeChallenges.keys()];
};
exports.retrieveChallengesWithCodeSnippet = retrieveChallengesWithCodeSnippet;
const getVerdict = (vulnLines, neutralLines, selectedLines) => {
    if (selectedLines === undefined)
        return false;
    if (vulnLines.length > selectedLines.length)
        return false;
    if (!vulnLines.every(e => selectedLines.includes(e)))
        return false;
    const okLines = [...vulnLines, ...neutralLines];
    const notOkLines = selectedLines.filter(x => !okLines.includes(x));
    return notOkLines.length === 0;
};
exports.getVerdict = getVerdict;
const checkVulnLines = () => async (req, res, next) => {
    const key = req.body.key;
    let snippetData;
    try {
        snippetData = await (0, exports.retrieveCodeSnippet)(key);
        if (snippetData == null) {
            res.status(404).json({ status: 'error', error: `No code challenge for challenge key: ${key}` });
            return;
        }
    }
    catch (error) {
        const statusCode = setStatusCode(error);
        res.status(statusCode).json({ status: 'error', error: utils.getErrorMessage(error) });
        return;
    }
    const vulnLines = snippetData.vulnLines;
    const neutralLines = snippetData.neutralLines;
    const selectedLines = req.body.selectedLines;
    const verdict = (0, exports.getVerdict)(vulnLines, neutralLines, selectedLines);
    let hint;
    if (node_fs_1.default.existsSync('./data/static/codefixes/' + key + '.info.yml')) {
        const codingChallengeInfos = js_yaml_1.default.load(node_fs_1.default.readFileSync('./data/static/codefixes/' + key + '.info.yml', 'utf8'));
        if (codingChallengeInfos?.hints) {
            if (accuracy.getFindItAttempts(key) > codingChallengeInfos.hints.length) {
                if (vulnLines.length === 1) {
                    hint = res.__('Line {{vulnLine}} is responsible for this vulnerability or security flaw. Select it and submit to proceed.', { vulnLine: vulnLines[0].toString() });
                }
                else {
                    hint = res.__('Lines {{vulnLines}} are responsible for this vulnerability or security flaw. Select them and submit to proceed.', { vulnLines: vulnLines.toString() });
                }
            }
            else {
                const nextHint = codingChallengeInfos.hints[accuracy.getFindItAttempts(key) - 1]; // -1 prevents after first attempt
                if (nextHint)
                    hint = res.__(nextHint);
            }
        }
    }
    if (verdict) {
        await challengeUtils.solveFindIt(key);
        res.status(200).json({
            verdict: true
        });
    }
    else {
        accuracy.storeFindItVerdict(key, false);
        res.status(200).json({
            verdict: false,
            hint
        });
    }
};
exports.checkVulnLines = checkVulnLines;
//# sourceMappingURL=vulnCodeSnippet.js.map