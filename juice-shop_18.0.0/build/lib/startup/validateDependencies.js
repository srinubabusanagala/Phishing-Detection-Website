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
const safe_1 = __importDefault(require("colors/safe"));
const utils = __importStar(require("../utils"));
const logger_1 = __importDefault(require("../logger"));
// @ts-expect-error FIXME due to non-existing type definitions for check-dependencies
const check_dependencies_1 = __importDefault(require("check-dependencies"));
const validateDependencies = async ({ packageDir = '.', exitOnFailure = true } = {}) => {
    let success = true;
    let dependencies = {};
    try {
        dependencies = await (0, check_dependencies_1.default)({ packageDir, scopeList: ['dependencies'] });
    }
    catch (err) {
        logger_1.default.warn(`Dependencies in ${safe_1.default.bold(packageDir + '/package.json')} could not be checked due to "${utils.getErrorMessage(err)}" error (${safe_1.default.red('NOT OK')})`);
    }
    if (dependencies.depsWereOk === true) {
        logger_1.default.info(`All dependencies in ${safe_1.default.bold(packageDir + '/package.json')} are satisfied (${safe_1.default.green('OK')})`);
    }
    else {
        logger_1.default.warn(`Dependencies in ${safe_1.default.bold(packageDir + '/package.json')} are not rightly satisfied (${safe_1.default.red('NOT OK')})`);
        success = false;
        for (const err of dependencies.error) {
            logger_1.default.warn(err);
        }
    }
    if (!success && exitOnFailure) {
        logger_1.default.error(safe_1.default.red('Exiting due to unsatisfied dependencies!'));
        process.exit(1);
    }
};
exports.default = validateDependencies;
//# sourceMappingURL=validateDependencies.js.map