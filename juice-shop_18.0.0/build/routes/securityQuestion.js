"use strict";
/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.securityQuestion = void 0;
const securityAnswer_1 = require("../models/securityAnswer");
const user_1 = require("../models/user");
const securityQuestion_1 = require("../models/securityQuestion");
function securityQuestion() {
    return ({ query }, res, next) => {
        const email = query.email;
        securityAnswer_1.SecurityAnswerModel.findOne({
            include: [{
                    model: user_1.UserModel,
                    where: { email: email?.toString() }
                }]
        }).then((answer) => {
            if (answer != null) {
                securityQuestion_1.SecurityQuestionModel.findByPk(answer.SecurityQuestionId).then((question) => {
                    res.json({ question });
                }).catch((error) => {
                    next(error);
                });
            }
            else {
                res.json({});
            }
        }).catch((error) => {
            next(error);
        });
    };
}
exports.securityQuestion = securityQuestion;
//# sourceMappingURL=securityQuestion.js.map