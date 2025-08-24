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
exports.updateAuthenticatedUsers = exports.appendUserId = exports.isCustomer = exports.isDeluxe = exports.isAccounting = exports.deluxeToken = exports.roles = exports.isRedirectAllowed = exports.redirectAllowlist = exports.discountFromCoupon = exports.generateCoupon = exports.userEmailFrom = exports.authenticatedUsers = exports.sanitizeSecure = exports.sanitizeFilename = exports.sanitizeLegacy = exports.sanitizeHtml = exports.decode = exports.verify = exports.authorize = exports.denyAll = exports.isAuthorized = exports.cutOffPoisonNullByte = exports.hmac = exports.hash = exports.publicKey = void 0;
const node_fs_1 = __importDefault(require("node:fs"));
const node_crypto_1 = __importDefault(require("node:crypto"));
const express_jwt_1 = __importDefault(require("express-jwt"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const jws_1 = __importDefault(require("jws"));
const sanitize_html_1 = __importDefault(require("sanitize-html"));
const sanitize_filename_1 = __importDefault(require("sanitize-filename"));
const utils = __importStar(require("./utils"));
/* jslint node: true */
// eslint-disable-next-line @typescript-eslint/prefer-ts-expect-error
// @ts-expect-error FIXME no typescript definitions for z85 :(
const z85 = __importStar(require("z85"));
exports.publicKey = node_fs_1.default ? node_fs_1.default.readFileSync('encryptionkeys/jwt.pub', 'utf8') : 'placeholder-public-key';
const privateKey = '-----BEGIN RSA PRIVATE KEY-----\r\nMIICXAIBAAKBgQDNwqLEe9wgTXCbC7+RPdDbBbeqjdbs4kOPOIGzqLpXvJXlxxW8iMz0EaM4BKUqYsIa+ndv3NAn2RxCd5ubVdJJcX43zO6Ko0TFEZx/65gY3BE0O6syCEmUP4qbSd6exou/F+WTISzbQ5FBVPVmhnYhG/kpwt/cIxK5iUn5hm+4tQIDAQABAoGBAI+8xiPoOrA+KMnG/T4jJsG6TsHQcDHvJi7o1IKC/hnIXha0atTX5AUkRRce95qSfvKFweXdJXSQ0JMGJyfuXgU6dI0TcseFRfewXAa/ssxAC+iUVR6KUMh1PE2wXLitfeI6JLvVtrBYswm2I7CtY0q8n5AGimHWVXJPLfGV7m0BAkEA+fqFt2LXbLtyg6wZyxMA/cnmt5Nt3U2dAu77MzFJvibANUNHE4HPLZxjGNXN+a6m0K6TD4kDdh5HfUYLWWRBYQJBANK3carmulBwqzcDBjsJ0YrIONBpCAsXxk8idXb8jL9aNIg15Wumm2enqqObahDHB5jnGOLmbasizvSVqypfM9UCQCQl8xIqy+YgURXzXCN+kwUgHinrutZms87Jyi+D8Br8NY0+Nlf+zHvXAomD2W5CsEK7C+8SLBr3k/TsnRWHJuECQHFE9RA2OP8WoaLPuGCyFXaxzICThSRZYluVnWkZtxsBhW2W8z1b8PvWUE7kMy7TnkzeJS2LSnaNHoyxi7IaPQUCQCwWU4U+v4lD7uYBw00Ga/xt+7+UqFPlPVdz1yyr4q24Zxaw0LgmuEvgU5dycq8N7JxjTubX0MIRR+G9fmDBBl8=\r\n-----END RSA PRIVATE KEY-----';
const hash = (data) => node_crypto_1.default.createHash('md5').update(data).digest('hex');
exports.hash = hash;
const hmac = (data) => node_crypto_1.default.createHmac('sha256', 'pa4qacea4VK9t9nGv7yZtwmj').update(data).digest('hex');
exports.hmac = hmac;
const cutOffPoisonNullByte = (str) => {
    const nullByte = '%00';
    if (utils.contains(str, nullByte)) {
        return str.substring(0, str.indexOf(nullByte));
    }
    return str;
};
exports.cutOffPoisonNullByte = cutOffPoisonNullByte;
const isAuthorized = () => (0, express_jwt_1.default)(({ secret: exports.publicKey }));
exports.isAuthorized = isAuthorized;
const denyAll = () => (0, express_jwt_1.default)({ secret: '' + Math.random() });
exports.denyAll = denyAll;
const authorize = (user = {}) => jsonwebtoken_1.default.sign(user, privateKey, { expiresIn: '6h', algorithm: 'RS256' });
exports.authorize = authorize;
const verify = (token) => token ? jws_1.default.verify(token, exports.publicKey) : false;
exports.verify = verify;
const decode = (token) => { return jws_1.default.decode(token)?.payload; };
exports.decode = decode;
const sanitizeHtml = (html) => (0, sanitize_html_1.default)(html);
exports.sanitizeHtml = sanitizeHtml;
const sanitizeLegacy = (input = '') => input.replace(/<(?:\w+)\W+?[\w]/gi, '');
exports.sanitizeLegacy = sanitizeLegacy;
const sanitizeFilename = (filename) => (0, sanitize_filename_1.default)(filename);
exports.sanitizeFilename = sanitizeFilename;
const sanitizeSecure = (html) => {
    const sanitized = (0, exports.sanitizeHtml)(html);
    if (sanitized === html) {
        return html;
    }
    else {
        return (0, exports.sanitizeSecure)(sanitized);
    }
};
exports.sanitizeSecure = sanitizeSecure;
exports.authenticatedUsers = {
    tokenMap: {},
    idMap: {},
    put: function (token, user) {
        this.tokenMap[token] = user;
        this.idMap[user.data.id] = token;
    },
    get: function (token) {
        return token ? this.tokenMap[utils.unquote(token)] : undefined;
    },
    tokenOf: function (user) {
        return user ? this.idMap[user.id] : undefined;
    },
    from: function (req) {
        const token = utils.jwtFrom(req);
        return token ? this.get(token) : undefined;
    },
    updateFrom: function (req, user) {
        const token = utils.jwtFrom(req);
        this.put(token, user);
    }
};
const userEmailFrom = ({ headers }) => {
    return headers ? headers['x-user-email'] : undefined;
};
exports.userEmailFrom = userEmailFrom;
const generateCoupon = (discount, date = new Date()) => {
    const coupon = utils.toMMMYY(date) + '-' + discount;
    return z85.encode(coupon);
};
exports.generateCoupon = generateCoupon;
const discountFromCoupon = (coupon) => {
    if (!coupon) {
        return undefined;
    }
    const decoded = z85.decode(coupon);
    if (decoded && (hasValidFormat(decoded.toString()) != null)) {
        const parts = decoded.toString().split('-');
        const validity = parts[0];
        if (utils.toMMMYY(new Date()) === validity) {
            const discount = parts[1];
            return parseInt(discount);
        }
    }
};
exports.discountFromCoupon = discountFromCoupon;
function hasValidFormat(coupon) {
    return coupon.match(/(JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC)[0-9]{2}-[0-9]{2}/);
}
// vuln-code-snippet start redirectCryptoCurrencyChallenge redirectChallenge
exports.redirectAllowlist = new Set([
    'https://github.com/juice-shop/juice-shop',
    'https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm', // vuln-code-snippet vuln-line redirectCryptoCurrencyChallenge
    'https://explorer.dash.org/address/Xr556RzuwX6hg5EGpkybbv5RanJoZN17kW', // vuln-code-snippet vuln-line redirectCryptoCurrencyChallenge
    'https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6', // vuln-code-snippet vuln-line redirectCryptoCurrencyChallenge
    'http://shop.spreadshirt.com/juiceshop',
    'http://shop.spreadshirt.de/juiceshop',
    'https://www.stickeryou.com/products/owasp-juice-shop/794',
    'http://leanpub.com/juice-shop'
]);
const isRedirectAllowed = (url) => {
    let allowed = false;
    for (const allowedUrl of exports.redirectAllowlist) {
        allowed = allowed || url.includes(allowedUrl); // vuln-code-snippet vuln-line redirectChallenge
    }
    return allowed;
};
exports.isRedirectAllowed = isRedirectAllowed;
// vuln-code-snippet end redirectCryptoCurrencyChallenge redirectChallenge
exports.roles = {
    customer: 'customer',
    deluxe: 'deluxe',
    accounting: 'accounting',
    admin: 'admin'
};
const deluxeToken = (email) => {
    const hmac = node_crypto_1.default.createHmac('sha256', privateKey);
    return hmac.update(email + exports.roles.deluxe).digest('hex');
};
exports.deluxeToken = deluxeToken;
const isAccounting = () => {
    return (req, res, next) => {
        const decodedToken = (0, exports.verify)(utils.jwtFrom(req)) && (0, exports.decode)(utils.jwtFrom(req));
        if (decodedToken?.data?.role === exports.roles.accounting) {
            next();
        }
        else {
            res.status(403).json({ error: 'Malicious activity detected' });
        }
    };
};
exports.isAccounting = isAccounting;
const isDeluxe = (req) => {
    const decodedToken = (0, exports.verify)(utils.jwtFrom(req)) && (0, exports.decode)(utils.jwtFrom(req));
    return decodedToken?.data?.role === exports.roles.deluxe && decodedToken?.data?.deluxeToken && decodedToken?.data?.deluxeToken === (0, exports.deluxeToken)(decodedToken?.data?.email);
};
exports.isDeluxe = isDeluxe;
const isCustomer = (req) => {
    const decodedToken = (0, exports.verify)(utils.jwtFrom(req)) && (0, exports.decode)(utils.jwtFrom(req));
    return decodedToken?.data?.role === exports.roles.customer;
};
exports.isCustomer = isCustomer;
const appendUserId = () => {
    return (req, res, next) => {
        try {
            req.body.UserId = exports.authenticatedUsers.tokenMap[utils.jwtFrom(req)].data.id;
            next();
        }
        catch (error) {
            res.status(401).json({ status: 'error', message: error });
        }
    };
};
exports.appendUserId = appendUserId;
const updateAuthenticatedUsers = () => (req, res, next) => {
    const token = req.cookies.token || utils.jwtFrom(req);
    if (token) {
        jsonwebtoken_1.default.verify(token, exports.publicKey, (err, decoded) => {
            if (err === null) {
                if (exports.authenticatedUsers.get(token) === undefined) {
                    exports.authenticatedUsers.put(token, decoded);
                    res.cookie('token', token);
                }
            }
        });
    }
    next();
};
exports.updateAuthenticatedUsers = updateAuthenticatedUsers;
//# sourceMappingURL=insecurity.js.map