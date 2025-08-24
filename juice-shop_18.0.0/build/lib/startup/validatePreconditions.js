"use strict";
/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.checkIfRequiredFileExists = exports.checkIfPortIsAvailable = exports.checkIfDomainReachable = exports.checkIfRunningOnSupportedCPU = exports.checkIfRunningOnSupportedOS = exports.checkIfRunningOnSupportedNodeVersion = void 0;
const package_json_1 = __importDefault(require("../../package.json"));
const config_1 = __importDefault(require("config"));
const logger_1 = __importDefault(require("../logger"));
const node_path_1 = __importDefault(require("node:path"));
const safe_1 = __importDefault(require("colors/safe"));
const promises_1 = require("node:fs/promises");
const node_process_1 = __importDefault(require("node:process"));
const semver_1 = __importDefault(require("semver"));
const portscanner_1 = __importDefault(require("portscanner"));
// @ts-expect-error FIXME due to non-existing type definitions for check-internet-connected
const check_internet_connected_1 = __importDefault(require("check-internet-connected"));
const domainDependencies = {
    'https://www.alchemy.com/': ['"Mint the Honeypot" challenge', '"Wallet Depletion" challenge']
};
const validatePreconditions = async ({ exitOnFailure = true } = {}) => {
    let success = true;
    success = (0, exports.checkIfRunningOnSupportedNodeVersion)(node_process_1.default.version) && success;
    success = (0, exports.checkIfRunningOnSupportedOS)(node_process_1.default.platform) && success;
    success = (0, exports.checkIfRunningOnSupportedCPU)(node_process_1.default.arch) && success;
    const asyncConditions = (await Promise.all([
        (0, exports.checkIfRequiredFileExists)('build/server.js'),
        (0, exports.checkIfRequiredFileExists)('frontend/dist/frontend/index.html'),
        (0, exports.checkIfRequiredFileExists)('frontend/dist/frontend/styles.css'),
        (0, exports.checkIfRequiredFileExists)('frontend/dist/frontend/main.js'),
        (0, exports.checkIfRequiredFileExists)('frontend/dist/frontend/tutorial.js'),
        (0, exports.checkIfRequiredFileExists)('frontend/dist/frontend/runtime.js'),
        (0, exports.checkIfRequiredFileExists)('frontend/dist/frontend/vendor.js'),
        (0, exports.checkIfPortIsAvailable)(node_process_1.default.env.PORT ?? config_1.default.get('server.port')),
        (0, exports.checkIfDomainReachable)('https://www.alchemy.com/')
    ])).every(condition => condition);
    if ((!success || !asyncConditions) && exitOnFailure) {
        logger_1.default.error(safe_1.default.red('Exiting due to unsatisfied precondition!'));
        node_process_1.default.exit(1);
    }
    return success;
};
const checkIfRunningOnSupportedNodeVersion = (runningVersion) => {
    const supportedVersion = package_json_1.default.engines.node;
    const effectiveVersionRange = semver_1.default.validRange(supportedVersion);
    if (!effectiveVersionRange) {
        logger_1.default.warn(`Invalid Node.js version range ${safe_1.default.bold(supportedVersion)} in package.json (${safe_1.default.red('NOT OK')})`);
        return false;
    }
    if (!semver_1.default.satisfies(runningVersion, effectiveVersionRange)) {
        logger_1.default.warn(`Detected Node version ${safe_1.default.bold(runningVersion)} is not in the supported version range of ${supportedVersion} (${safe_1.default.red('NOT OK')})`);
        return false;
    }
    logger_1.default.info(`Detected Node.js version ${safe_1.default.bold(runningVersion)} (${safe_1.default.green('OK')})`);
    return true;
};
exports.checkIfRunningOnSupportedNodeVersion = checkIfRunningOnSupportedNodeVersion;
const checkIfRunningOnSupportedOS = (runningOS) => {
    const supportedOS = package_json_1.default.os;
    if (!supportedOS.includes(runningOS)) {
        logger_1.default.warn(`Detected OS ${safe_1.default.bold(runningOS)} is not in the list of supported platforms ${supportedOS.toString()} (${safe_1.default.red('NOT OK')})`);
        return false;
    }
    logger_1.default.info(`Detected OS ${safe_1.default.bold(runningOS)} (${safe_1.default.green('OK')})`);
    return true;
};
exports.checkIfRunningOnSupportedOS = checkIfRunningOnSupportedOS;
const checkIfRunningOnSupportedCPU = (runningArch) => {
    const supportedArch = package_json_1.default.cpu;
    if (!supportedArch.includes(runningArch)) {
        logger_1.default.warn(`Detected CPU ${safe_1.default.bold(runningArch)} is not in the list of supported architectures ${supportedArch.toString()} (${safe_1.default.red('NOT OK')})`);
        return false;
    }
    logger_1.default.info(`Detected CPU ${safe_1.default.bold(runningArch)} (${safe_1.default.green('OK')})`);
    return true;
};
exports.checkIfRunningOnSupportedCPU = checkIfRunningOnSupportedCPU;
const checkIfDomainReachable = async (domain) => {
    return (0, check_internet_connected_1.default)({ domain })
        .then(() => {
        logger_1.default.info(`Domain ${safe_1.default.bold(domain)} is reachable (${safe_1.default.green('OK')})`);
        return true;
    })
        .catch(() => {
        logger_1.default.warn(`Domain ${safe_1.default.bold(domain)} is not reachable (${safe_1.default.yellow('NOT OK')} in a future major release)`);
        // @ts-expect-error FIXME Type problem by accessing key via variable
        domainDependencies[domain].forEach((dependency) => {
            logger_1.default.warn(`${safe_1.default.italic(dependency)} will not work as intended without access to ${safe_1.default.bold(domain)}`);
        });
        return true; // TODO Consider switching to "false" with breaking release v16.0.0 or later
    });
};
exports.checkIfDomainReachable = checkIfDomainReachable;
const checkIfPortIsAvailable = async (port) => {
    const portNumber = parseInt(port.toString());
    return await new Promise((resolve, reject) => {
        portscanner_1.default.checkPortStatus(portNumber, function (error, status) {
            if (error) {
                reject(error);
            }
            else {
                if (status === 'open') {
                    logger_1.default.warn(`Port ${safe_1.default.bold(port.toString())} is in use (${safe_1.default.red('NOT OK')})`);
                    resolve(false);
                }
                else {
                    logger_1.default.info(`Port ${safe_1.default.bold(port.toString())} is available (${safe_1.default.green('OK')})`);
                    resolve(true);
                }
            }
        });
    });
};
exports.checkIfPortIsAvailable = checkIfPortIsAvailable;
const checkIfRequiredFileExists = async (pathRelativeToProjectRoot) => {
    const fileName = pathRelativeToProjectRoot.substr(pathRelativeToProjectRoot.lastIndexOf('/') + 1);
    return await (0, promises_1.access)(node_path_1.default.resolve(pathRelativeToProjectRoot)).then(() => {
        logger_1.default.info(`Required file ${safe_1.default.bold(fileName)} is present (${safe_1.default.green('OK')})`);
        return true;
    }).catch(() => {
        logger_1.default.warn(`Required file ${safe_1.default.bold(fileName)} is missing (${safe_1.default.red('NOT OK')})`);
        return false;
    });
};
exports.checkIfRequiredFileExists = checkIfRequiredFileExists;
exports.default = validatePreconditions;
//# sourceMappingURL=validatePreconditions.js.map