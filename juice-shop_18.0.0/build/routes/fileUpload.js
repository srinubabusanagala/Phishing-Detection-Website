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
exports.handleYamlUpload = exports.handleXmlUpload = exports.checkFileType = exports.checkUploadSize = exports.handleZipFileUpload = exports.ensureFileIsPassed = void 0;
const node_os_1 = __importDefault(require("node:os"));
const node_fs_1 = __importDefault(require("node:fs"));
const node_vm_1 = __importDefault(require("node:vm"));
const node_path_1 = __importDefault(require("node:path"));
const js_yaml_1 = __importDefault(require("js-yaml"));
const libxmljs2_1 = __importDefault(require("libxmljs2"));
const unzipper_1 = __importDefault(require("unzipper"));
const challengeUtils = __importStar(require("../lib/challengeUtils"));
const datacache_1 = require("../data/datacache");
const utils = __importStar(require("../lib/utils"));
function ensureFileIsPassed({ file }, res, next) {
    if (file != null) {
        next();
    }
    else {
        return res.status(400).json({ error: 'File is not passed' });
    }
}
exports.ensureFileIsPassed = ensureFileIsPassed;
function handleZipFileUpload({ file }, res, next) {
    if (utils.endsWith(file?.originalname.toLowerCase(), '.zip')) {
        if (((file?.buffer) != null) && utils.isChallengeEnabled(datacache_1.challenges.fileWriteChallenge)) {
            const buffer = file.buffer;
            const filename = file.originalname.toLowerCase();
            const tempFile = node_path_1.default.join(node_os_1.default.tmpdir(), filename);
            node_fs_1.default.open(tempFile, 'w', function (err, fd) {
                if (err != null) {
                    next(err);
                }
                node_fs_1.default.write(fd, buffer, 0, buffer.length, null, function (err) {
                    if (err != null) {
                        next(err);
                    }
                    node_fs_1.default.close(fd, function () {
                        node_fs_1.default.createReadStream(tempFile)
                            .pipe(unzipper_1.default.Parse())
                            .on('entry', function (entry) {
                            const fileName = entry.path;
                            const absolutePath = node_path_1.default.resolve('uploads/complaints/' + fileName);
                            challengeUtils.solveIf(datacache_1.challenges.fileWriteChallenge, () => { return absolutePath === node_path_1.default.resolve('ftp/legal.md'); });
                            if (absolutePath.includes(node_path_1.default.resolve('.'))) {
                                entry.pipe(node_fs_1.default.createWriteStream('uploads/complaints/' + fileName).on('error', function (err) { next(err); }));
                            }
                            else {
                                entry.autodrain();
                            }
                        }).on('error', function (err) { next(err); });
                    });
                });
            });
        }
        res.status(204).end();
    }
    else {
        next();
    }
}
exports.handleZipFileUpload = handleZipFileUpload;
function checkUploadSize({ file }, res, next) {
    if (file != null) {
        challengeUtils.solveIf(datacache_1.challenges.uploadSizeChallenge, () => { return file?.size > 100000; });
    }
    next();
}
exports.checkUploadSize = checkUploadSize;
function checkFileType({ file }, res, next) {
    const fileType = file?.originalname.substr(file.originalname.lastIndexOf('.') + 1).toLowerCase();
    challengeUtils.solveIf(datacache_1.challenges.uploadTypeChallenge, () => {
        return !(fileType === 'pdf' || fileType === 'xml' || fileType === 'zip' || fileType === 'yml' || fileType === 'yaml');
    });
    next();
}
exports.checkFileType = checkFileType;
function handleXmlUpload({ file }, res, next) {
    if (utils.endsWith(file?.originalname.toLowerCase(), '.xml')) {
        challengeUtils.solveIf(datacache_1.challenges.deprecatedInterfaceChallenge, () => { return true; });
        if (((file?.buffer) != null) && utils.isChallengeEnabled(datacache_1.challenges.deprecatedInterfaceChallenge)) { // XXE attacks in Docker/Heroku containers regularly cause "segfault" crashes
            const data = file.buffer.toString();
            try {
                const sandbox = { libxml: libxmljs2_1.default, data };
                node_vm_1.default.createContext(sandbox);
                const xmlDoc = node_vm_1.default.runInContext('libxml.parseXml(data, { noblanks: true, noent: true, nocdata: true })', sandbox, { timeout: 2000 });
                const xmlString = xmlDoc.toString(false);
                challengeUtils.solveIf(datacache_1.challenges.xxeFileDisclosureChallenge, () => { return (utils.matchesEtcPasswdFile(xmlString) || utils.matchesSystemIniFile(xmlString)); });
                res.status(410);
                next(new Error('B2B customer complaints via file upload have been deprecated for security reasons: ' + utils.trunc(xmlString, 400) + ' (' + file.originalname + ')'));
            }
            catch (err) { // TODO: Remove any
                if (utils.contains(err.message, 'Script execution timed out')) {
                    if (challengeUtils.notSolved(datacache_1.challenges.xxeDosChallenge)) {
                        challengeUtils.solve(datacache_1.challenges.xxeDosChallenge);
                    }
                    res.status(503);
                    next(new Error('Sorry, we are temporarily not available! Please try again later.'));
                }
                else {
                    res.status(410);
                    next(new Error('B2B customer complaints via file upload have been deprecated for security reasons: ' + err.message + ' (' + file.originalname + ')'));
                }
            }
        }
        else {
            res.status(410);
            next(new Error('B2B customer complaints via file upload have been deprecated for security reasons (' + file?.originalname + ')'));
        }
    }
    next();
}
exports.handleXmlUpload = handleXmlUpload;
function handleYamlUpload({ file }, res, next) {
    if (utils.endsWith(file?.originalname.toLowerCase(), '.yml') || utils.endsWith(file?.originalname.toLowerCase(), '.yaml')) {
        challengeUtils.solveIf(datacache_1.challenges.deprecatedInterfaceChallenge, () => { return true; });
        if (((file?.buffer) != null) && utils.isChallengeEnabled(datacache_1.challenges.deprecatedInterfaceChallenge)) {
            const data = file.buffer.toString();
            try {
                const sandbox = { yaml: js_yaml_1.default, data };
                node_vm_1.default.createContext(sandbox);
                const yamlString = node_vm_1.default.runInContext('JSON.stringify(yaml.load(data))', sandbox, { timeout: 2000 });
                res.status(410);
                next(new Error('B2B customer complaints via file upload have been deprecated for security reasons: ' + utils.trunc(yamlString, 400) + ' (' + file.originalname + ')'));
            }
            catch (err) { // TODO: Remove any
                if (utils.contains(err.message, 'Invalid string length') || utils.contains(err.message, 'Script execution timed out')) {
                    if (challengeUtils.notSolved(datacache_1.challenges.yamlBombChallenge)) {
                        challengeUtils.solve(datacache_1.challenges.yamlBombChallenge);
                    }
                    res.status(503);
                    next(new Error('Sorry, we are temporarily not available! Please try again later.'));
                }
                else {
                    res.status(410);
                    next(new Error('B2B customer complaints via file upload have been deprecated for security reasons: ' + err.message + ' (' + file.originalname + ')'));
                }
            }
        }
        else {
            res.status(410);
            next(new Error('B2B customer complaints via file upload have been deprecated for security reasons (' + file?.originalname + ')'));
        }
    }
    res.status(204).end();
}
exports.handleYamlUpload = handleYamlUpload;
//# sourceMappingURL=fileUpload.js.map