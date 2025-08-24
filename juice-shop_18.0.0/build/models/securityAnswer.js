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
Object.defineProperty(exports, "__esModule", { value: true });
exports.SecurityAnswerModelInit = exports.SecurityAnswerModel = void 0;
/* jslint node: true */
const sequelize_1 = require("sequelize");
const security = __importStar(require("../lib/insecurity"));
class SecurityAnswer extends sequelize_1.Model {
}
exports.SecurityAnswerModel = SecurityAnswer;
const SecurityAnswerModelInit = (sequelize) => {
    SecurityAnswer.init({
        UserId: {
            type: sequelize_1.DataTypes.INTEGER,
            unique: true
        },
        SecurityQuestionId: {
            type: sequelize_1.DataTypes.INTEGER
        },
        id: {
            type: sequelize_1.DataTypes.INTEGER,
            primaryKey: true,
            autoIncrement: true
        },
        answer: {
            type: sequelize_1.DataTypes.STRING,
            set(answer) {
                this.setDataValue('answer', security.hmac(answer));
            }
        }
    }, {
        tableName: 'SecurityAnswers',
        sequelize
    });
};
exports.SecurityAnswerModelInit = SecurityAnswerModelInit;
//# sourceMappingURL=securityAnswer.js.map