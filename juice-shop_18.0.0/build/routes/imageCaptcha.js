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
exports.verifyImageCaptcha = exports.imageCaptchas = void 0;
const svg_captcha_1 = __importDefault(require("svg-captcha"));
const sequelize_1 = require("sequelize");
const imageCaptcha_1 = require("../models/imageCaptcha");
const security = __importStar(require("../lib/insecurity"));
function imageCaptchas() {
    return (req, res) => {
        const captcha = svg_captcha_1.default.create({ size: 5, noise: 2, color: true });
        const user = security.authenticatedUsers.from(req);
        if (!user) {
            res.status(401).send(res.__('You need to be logged in to request a CAPTCHA.'));
            return;
        }
        const imageCaptcha = {
            image: captcha.data,
            answer: captcha.text,
            UserId: user.data.id
        };
        const imageCaptchaInstance = imageCaptcha_1.ImageCaptchaModel.build(imageCaptcha);
        imageCaptchaInstance.save().then(() => {
            res.json(imageCaptcha);
        }).catch(() => {
            res.status(400).send(res.__('Unable to create CAPTCHA. Please try again.'));
        });
    };
}
exports.imageCaptchas = imageCaptchas;
const verifyImageCaptcha = () => (req, res, next) => {
    const user = security.authenticatedUsers.from(req);
    const UserId = user ? user.data ? user.data.id : undefined : undefined;
    imageCaptcha_1.ImageCaptchaModel.findAll({
        limit: 1,
        where: {
            UserId,
            createdAt: {
                [sequelize_1.Op.gt]: new Date(Date.now() - 300000)
            }
        },
        order: [['createdAt', 'DESC']]
    }).then(captchas => {
        if (!captchas[0] || req.body.answer === captchas[0].answer) {
            next();
        }
        else {
            res.status(401).send(res.__('Wrong answer to CAPTCHA. Please try again.'));
        }
    }).catch(() => {
        res.status(401).send(res.__('Something went wrong while submitting CAPTCHA. Please try again.'));
    });
};
exports.verifyImageCaptcha = verifyImageCaptcha;
//# sourceMappingURL=imageCaptcha.js.map