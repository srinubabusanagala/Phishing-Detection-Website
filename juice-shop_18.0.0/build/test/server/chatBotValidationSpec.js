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
const sinon_chai_1 = __importDefault(require("sinon-chai"));
const validateChatBot_1 = __importStar(require("../../lib/startup/validateChatBot"));
const botDefaultTrainingData_json_1 = __importDefault(require("../../data/static/botDefaultTrainingData.json"));
const expect = chai_1.default.expect;
chai_1.default.use(sinon_chai_1.default);
describe('chatBotValidation', () => {
    describe('checkIntentWithHandlerExists', () => {
        it('should accept training data with the expected intent and handler', () => {
            const trainingData = {
                data: [
                    {
                        intent: 'queries.test',
                        answers: [
                            {
                                action: 'function',
                                handler: 'testHandler'
                            }
                        ]
                    }
                ]
            };
            expect((0, validateChatBot_1.checkIntentWithFunctionHandlerExists)(trainingData, 'queries.test', 'testHandler')).to.equal(true);
        });
        it('should fail if the training data lacks the expected intent', () => {
            const trainingData = {
                data: [
                    {
                        intent: 'queries.dummy'
                    }
                ]
            };
            expect((0, validateChatBot_1.checkIntentWithFunctionHandlerExists)(trainingData, 'queries.test', 'testFunction')).to.equal(false);
        });
        it('should fail if the training data lacks the expected handler for the given intent', () => {
            const trainingData = {
                data: [
                    {
                        intent: 'queries.test',
                        answers: [
                            {
                                action: 'function',
                                handler: 'dummyHandler'
                            }
                        ]
                    }
                ]
            };
            expect((0, validateChatBot_1.checkIntentWithFunctionHandlerExists)(trainingData, 'queries.test', 'testHandler')).to.equal(false);
        });
    });
    it('should accept the default chatbot training data', () => {
        expect((0, validateChatBot_1.default)(botDefaultTrainingData_json_1.default)).to.equal(true);
    });
    it('should fail if the chatbot training data is empty', () => {
        expect((0, validateChatBot_1.default)({ data: [] }, false)).to.equal(false);
    });
});
//# sourceMappingURL=chatBotValidationSpec.js.map