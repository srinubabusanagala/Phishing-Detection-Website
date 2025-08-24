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
exports.FeedbackModelInit = exports.FeedbackModel = void 0;
/* jslint node: true */
const utils = __importStar(require("../lib/utils"));
const challengeUtils = __importStar(require("../lib/challengeUtils"));
const sequelize_1 = require("sequelize");
const datacache_1 = require("../data/datacache");
const security = __importStar(require("../lib/insecurity"));
class Feedback extends sequelize_1.Model {
}
exports.FeedbackModel = Feedback;
const FeedbackModelInit = (sequelize) => {
    Feedback.init({
        UserId: {
            type: sequelize_1.DataTypes.INTEGER
        },
        id: {
            type: sequelize_1.DataTypes.INTEGER,
            primaryKey: true,
            autoIncrement: true
        },
        comment: {
            type: sequelize_1.DataTypes.STRING,
            set(comment) {
                let sanitizedComment;
                if (utils.isChallengeEnabled(datacache_1.challenges.persistedXssFeedbackChallenge)) {
                    sanitizedComment = security.sanitizeHtml(comment);
                    challengeUtils.solveIf(datacache_1.challenges.persistedXssFeedbackChallenge, () => {
                        return utils.contains(sanitizedComment, '<iframe src="javascript:alert(`xss`)">');
                    });
                }
                else {
                    sanitizedComment = security.sanitizeSecure(comment);
                }
                this.setDataValue('comment', sanitizedComment);
            }
        },
        rating: {
            type: sequelize_1.DataTypes.INTEGER,
            allowNull: false,
            set(rating) {
                this.setDataValue('rating', rating);
                challengeUtils.solveIf(datacache_1.challenges.zeroStarsChallenge, () => {
                    return Number(rating) === 0;
                });
            }
        }
    }, {
        tableName: 'Feedbacks',
        sequelize
    });
};
exports.FeedbackModelInit = FeedbackModelInit;
//# sourceMappingURL=feedback.js.map