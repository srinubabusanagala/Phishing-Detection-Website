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
exports.checkIntentWithFunctionHandlerExists = void 0;
const config_1 = __importDefault(require("config"));
const logger_1 = __importDefault(require("../logger"));
const safe_1 = __importDefault(require("colors/safe"));
const utils = __importStar(require("../utils"));
function validateChatBot(trainingData, exitOnFailure = true) {
    let success = true;
    success = (0, exports.checkIntentWithFunctionHandlerExists)(trainingData, 'queries.couponCode', 'couponCode') && success;
    success = (0, exports.checkIntentWithFunctionHandlerExists)(trainingData, 'queries.productPrice', 'productPrice') && success;
    success = (0, exports.checkIntentWithFunctionHandlerExists)(trainingData, 'queries.functionTest', 'testFunction') && success;
    if (success) {
        logger_1.default.info(`Chatbot training data ${safe_1.default.bold(utils.extractFilename(config_1.default.get('application.chatBot.trainingData')))} validated (${safe_1.default.green('OK')})`);
    }
    else {
        logger_1.default.warn(`Chatbot training data ${safe_1.default.bold(utils.extractFilename(config_1.default.get('application.chatBot.trainingData')))} validated (${safe_1.default.red('NOT OK')})`);
        logger_1.default.warn(`Visit ${safe_1.default.yellow('https://pwning.owasp-juice.shop/companion-guide/latest/part5/chatbot.html')} for the training data schema definition.`);
        if (exitOnFailure) {
            logger_1.default.error(safe_1.default.red('Exiting due to configuration errors!'));
            process.exit(1);
        }
    }
    return success;
}
exports.default = validateChatBot;
const checkIntentWithFunctionHandlerExists = (trainingData, intent, handler) => {
    let success = true;
    const intentData = trainingData.data.filter((data) => data.intent === intent);
    if (intentData.length === 0) {
        logger_1.default.warn(`Intent ${safe_1.default.italic(intent)} is missing in chatbot training data (${safe_1.default.red('NOT OK')})`);
        success = false;
    }
    else {
        if (intentData[0].answers.filter((answer) => answer.action === 'function' && answer.handler === handler).length === 0) {
            logger_1.default.warn(`Answer with ${safe_1.default.italic('function')} action and handler ${safe_1.default.italic(handler)} is missing for intent ${safe_1.default.italic(intent)} (${safe_1.default.red('NOT OK')})`);
            success = false;
        }
    }
    return success;
};
exports.checkIntentWithFunctionHandlerExists = checkIntentWithFunctionHandlerExists;
//# sourceMappingURL=validateChatBot.js.map