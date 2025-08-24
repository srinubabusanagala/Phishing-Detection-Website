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
exports.UserModelInit = exports.UserModel = void 0;
/* jslint node: true */
const config_1 = __importDefault(require("config"));
const sequelize_1 = require("sequelize");
const challengeUtils = __importStar(require("../lib/challengeUtils"));
const utils = __importStar(require("../lib/utils"));
const datacache_1 = require("../data/datacache");
const security = __importStar(require("../lib/insecurity"));
class User extends sequelize_1.Model {
}
exports.UserModel = User;
const UserModelInit = (sequelize) => {
    User.init({
        id: {
            type: sequelize_1.DataTypes.INTEGER,
            primaryKey: true,
            autoIncrement: true
        },
        username: {
            type: sequelize_1.DataTypes.STRING,
            defaultValue: '',
            set(username) {
                if (utils.isChallengeEnabled(datacache_1.challenges.persistedXssUserChallenge)) {
                    username = security.sanitizeLegacy(username);
                }
                else {
                    username = security.sanitizeSecure(username);
                }
                this.setDataValue('username', username);
            }
        },
        email: {
            type: sequelize_1.DataTypes.STRING,
            unique: true,
            set(email) {
                if (utils.isChallengeEnabled(datacache_1.challenges.persistedXssUserChallenge)) {
                    challengeUtils.solveIf(datacache_1.challenges.persistedXssUserChallenge, () => {
                        return utils.contains(email, '<iframe src="javascript:alert(`xss`)">');
                    });
                }
                else {
                    email = security.sanitizeSecure(email);
                }
                this.setDataValue('email', email);
            }
        }, // vuln-code-snippet hide-end
        password: {
            type: sequelize_1.DataTypes.STRING,
            set(clearTextPassword) {
                this.setDataValue('password', security.hash(clearTextPassword)); // vuln-code-snippet vuln-line weakPasswordChallenge
            }
        }, // vuln-code-snippet end weakPasswordChallenge
        role: {
            type: sequelize_1.DataTypes.STRING,
            defaultValue: 'customer',
            validate: {
                isIn: [['customer', 'deluxe', 'accounting', 'admin']]
            },
            set(role) {
                const profileImage = this.getDataValue('profileImage');
                if (role === security.roles.admin &&
                    (!profileImage ||
                        profileImage === '/assets/public/images/uploads/default.svg')) {
                    this.setDataValue('profileImage', '/assets/public/images/uploads/defaultAdmin.png');
                }
                this.setDataValue('role', role);
            }
        },
        deluxeToken: {
            type: sequelize_1.DataTypes.STRING,
            defaultValue: ''
        },
        lastLoginIp: {
            type: sequelize_1.DataTypes.STRING,
            defaultValue: '0.0.0.0'
        },
        profileImage: {
            type: sequelize_1.DataTypes.STRING,
            defaultValue: '/assets/public/images/uploads/default.svg'
        },
        totpSecret: {
            type: sequelize_1.DataTypes.STRING,
            defaultValue: ''
        },
        isActive: {
            type: sequelize_1.DataTypes.BOOLEAN,
            defaultValue: true
        }
    }, {
        tableName: 'Users',
        paranoid: true,
        sequelize
    });
    User.addHook('afterValidate', async (user) => {
        if (user.email &&
            user.email.toLowerCase() ===
                `acc0unt4nt@${config_1.default.get('application.domain')}`.toLowerCase()) {
            await Promise.reject(new Error('Nice try, but this is not how the "Ephemeral Accountant" challenge works!'));
        }
    });
};
exports.UserModelInit = UserModelInit;
//# sourceMappingURL=user.js.map