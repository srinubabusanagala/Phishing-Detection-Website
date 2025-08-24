"use strict";
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
const user_1 = require("../models/user");
const jsonwebtoken_1 = require("jsonwebtoken");
const security = __importStar(require("../lib/insecurity"));
async function retrieveUserList(req, res, next) {
    try {
        const users = await user_1.UserModel.findAll();
        res.json({
            status: 'success',
            data: users.map((user) => {
                const userToken = security.authenticatedUsers.tokenOf(user);
                let lastLoginTime = null;
                if (userToken) {
                    const parsedToken = (0, jsonwebtoken_1.decode)(userToken, { json: true });
                    lastLoginTime = parsedToken ? Math.floor(new Date(parsedToken?.iat ?? 0 * 1000).getTime()) : null;
                }
                return {
                    ...user.dataValues,
                    password: user.password?.replace(/./g, '*'),
                    totpSecret: user.totpSecret?.replace(/./g, '*'),
                    lastLoginTime
                };
            })
        });
    }
    catch (error) {
        next(error);
    }
}
exports.default = () => retrieveUserList;
//# sourceMappingURL=authenticatedUsers.js.map