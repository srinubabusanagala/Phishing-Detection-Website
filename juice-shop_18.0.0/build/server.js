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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.close = exports.start = void 0;
/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
const i18n_1 = __importDefault(require("i18n"));
const cors_1 = __importDefault(require("cors"));
const node_fs_1 = __importDefault(require("node:fs"));
const js_yaml_1 = __importDefault(require("js-yaml"));
const config_1 = __importDefault(require("config"));
const morgan_1 = __importDefault(require("morgan"));
const multer_1 = __importDefault(require("multer"));
const helmet_1 = __importDefault(require("helmet"));
const node_http_1 = __importDefault(require("node:http"));
const node_path_1 = __importDefault(require("node:path"));
const express_1 = __importDefault(require("express"));
const safe_1 = __importDefault(require("colors/safe"));
const serve_index_1 = __importDefault(require("serve-index"));
const body_parser_1 = __importDefault(require("body-parser"));
// @ts-expect-error FIXME due to non-existing type definitions for finale-rest
const finale = __importStar(require("finale-rest"));
const compression_1 = __importDefault(require("compression"));
// @ts-expect-error FIXME due to non-existing type definitions for express-robots-txt
const express_robots_txt_1 = __importDefault(require("express-robots-txt"));
const cookie_parser_1 = __importDefault(require("cookie-parser"));
const Prometheus = __importStar(require("prom-client"));
const swagger_ui_express_1 = __importDefault(require("swagger-ui-express"));
const feature_policy_1 = __importDefault(require("feature-policy"));
const express_ipfilter_1 = require("express-ipfilter");
// @ts-expect-error FIXME due to non-existing type definitions for express-security.txt
const express_security_txt_1 = __importDefault(require("express-security.txt"));
const express_rate_limit_1 = require("express-rate-limit");
const file_stream_rotator_1 = require("file-stream-rotator");
const models_1 = require("./models");
const user_1 = require("./models/user");
const card_1 = require("./models/card");
const wallet_1 = require("./models/wallet");
const product_1 = require("./models/product");
const recycle_1 = require("./models/recycle");
const address_1 = require("./models/address");
const quantity_1 = require("./models/quantity");
const feedback_1 = require("./models/feedback");
const complaint_1 = require("./models/complaint");
const challenge_1 = require("./models/challenge");
const basketitem_1 = require("./models/basketitem");
const securityAnswer_1 = require("./models/securityAnswer");
const privacyRequests_1 = require("./models/privacyRequests");
const securityQuestion_1 = require("./models/securityQuestion");
const logger_1 = __importDefault(require("./lib/logger"));
const utils = __importStar(require("./lib/utils"));
const antiCheat = __importStar(require("./lib/antiCheat"));
const security = __importStar(require("./lib/insecurity"));
const validateConfig_1 = __importDefault(require("./lib/startup/validateConfig"));
const cleanupFtpFolder_1 = __importDefault(require("./lib/startup/cleanupFtpFolder"));
const customizeEasterEgg_1 = __importDefault(require("./lib/startup/customizeEasterEgg")); // vuln-code-snippet hide-line
const customizeApplication_1 = __importDefault(require("./lib/startup/customizeApplication"));
const validatePreconditions_1 = __importDefault(require("./lib/startup/validatePreconditions"));
const registerWebsocketEvents_1 = __importDefault(require("./lib/startup/registerWebsocketEvents"));
const restoreOverwrittenFilesWithOriginals_1 = __importDefault(require("./lib/startup/restoreOverwrittenFilesWithOriginals"));
const datacreator_1 = __importDefault(require("./data/datacreator"));
const locales_json_1 = __importDefault(require("./data/static/locales.json"));
const login_1 = require("./routes/login");
const verify = __importStar(require("./routes/verify"));
const address = __importStar(require("./routes/address"));
const chatbot = __importStar(require("./routes/chatbot"));
const metrics = __importStar(require("./routes/metrics"));
const payment = __importStar(require("./routes/payment"));
const order_1 = require("./routes/order");
const b2bOrder_1 = require("./routes/b2bOrder");
const delivery = __importStar(require("./routes/delivery"));
const recycles = __importStar(require("./routes/recycles"));
const twoFactorAuth = __importStar(require("./routes/2fa"));
const coupon_1 = require("./routes/coupon");
const dataErasure_1 = __importDefault(require("./routes/dataErasure"));
const dataExport_1 = require("./routes/dataExport");
const basket_1 = require("./routes/basket");
const search_1 = require("./routes/search");
const trackOrder_1 = require("./routes/trackOrder");
const saveLoginIp_1 = require("./routes/saveLoginIp");
const keyServer_1 = require("./routes/keyServer");
const basketItems = __importStar(require("./routes/basketItems"));
const redirect_1 = require("./routes/redirect");
const easterEgg_1 = require("./routes/easterEgg");
const languages_1 = require("./routes/languages");
const userProfile_1 = require("./routes/userProfile");
const angular_1 = require("./routes/angular");
const resetPassword_1 = require("./routes/resetPassword");
const logfileServer_1 = require("./routes/logfileServer");
const fileServer_1 = require("./routes/fileServer");
const memory_1 = require("./routes/memory");
const changePassword_1 = require("./routes/changePassword");
const countryMapping_1 = require("./routes/countryMapping");
const appVersion_1 = require("./routes/appVersion");
const captcha_1 = require("./routes/captcha");
const restoreProgress = __importStar(require("./routes/restoreProgress"));
const checkKeys_1 = require("./routes/checkKeys");
const currentUser_1 = require("./routes/currentUser");
const authenticatedUsers_1 = __importDefault(require("./routes/authenticatedUsers"));
const securityQuestion_2 = require("./routes/securityQuestion");
const premiumReward_1 = require("./routes/premiumReward");
const web3Wallet_1 = require("./routes/web3Wallet");
const updateUserProfile_1 = require("./routes/updateUserProfile");
const videoHandler_1 = require("./routes/videoHandler");
const likeProductReviews_1 = require("./routes/likeProductReviews");
const repeatNotification_1 = require("./routes/repeatNotification");
const quarantineServer_1 = require("./routes/quarantineServer");
const showProductReviews_1 = require("./routes/showProductReviews");
const nftMint_1 = require("./routes/nftMint");
const createProductReviews_1 = require("./routes/createProductReviews");
const wallet_2 = require("./routes/wallet");
const appConfiguration_1 = require("./routes/appConfiguration");
const updateProductReviews_1 = require("./routes/updateProductReviews");
const privacyPolicyProof_1 = require("./routes/privacyPolicyProof");
const profileImageUrlUpload_1 = require("./routes/profileImageUrlUpload");
const profileImageFileUpload_1 = require("./routes/profileImageFileUpload");
const vulnCodeFixes_1 = require("./routes/vulnCodeFixes");
const imageCaptcha_1 = require("./routes/imageCaptcha");
const deluxe_1 = require("./routes/deluxe");
const vulnCodeSnippet_1 = require("./routes/vulnCodeSnippet");
const orderHistory_1 = require("./routes/orderHistory");
const continueCode_1 = require("./routes/continueCode");
const fileUpload_1 = require("./routes/fileUpload");
const app = (0, express_1.default)();
const server = new node_http_1.default.Server(app);
// errorhandler requires us from overwriting a string property on it's module which is a big no-no with esmodules :/
const errorhandler = require('errorhandler');
const startTime = Date.now();
const swaggerDocument = js_yaml_1.default.load(node_fs_1.default.readFileSync('./swagger.yml', 'utf8'));
const appName = config_1.default.get('application.customMetricsPrefix');
const startupGauge = new Prometheus.Gauge({
    name: `${appName}_startup_duration_seconds`,
    help: `Duration ${appName} required to perform a certain task during startup`,
    labelNames: ['task']
});
// Wraps the function and measures its (async) execution time
const collectDurationPromise = (name, func) => {
    return async (...args) => {
        const end = startupGauge.startTimer({ task: name });
        try {
            const res = await func(...args);
            end();
            return res;
        }
        catch (err) {
            console.error('Error in timed startup function: ' + name, err);
            throw err;
        }
    };
};
/* Sets view engine to hbs */
app.set('view engine', 'hbs');
void collectDurationPromise('validatePreconditions', validatePreconditions_1.default)();
void collectDurationPromise('cleanupFtpFolder', cleanupFtpFolder_1.default)();
void collectDurationPromise('validateConfig', validateConfig_1.default)({});
// Function called first to ensure that all the i18n files are reloaded successfully before other linked operations.
(0, restoreOverwrittenFilesWithOriginals_1.default)().then(() => {
    /* Locals */
    app.locals.captchaId = 0;
    app.locals.captchaReqId = 1;
    app.locals.captchaBypassReqTimes = [];
    app.locals.abused_ssti_bug = false;
    app.locals.abused_ssrf_bug = false;
    /* Compression for all requests */
    app.use((0, compression_1.default)());
    /* Bludgeon solution for possible CORS problems: Allow everything! */
    app.options('*', (0, cors_1.default)());
    app.use((0, cors_1.default)());
    /* Security middleware */
    app.use(helmet_1.default.noSniff());
    app.use(helmet_1.default.frameguard());
    // app.use(helmet.xssFilter()); // = no protection from persisted XSS via RESTful API
    app.disable('x-powered-by');
    app.use((0, feature_policy_1.default)({
        features: {
            payment: ["'self'"]
        }
    }));
    /* Hiring header */
    app.use((req, res, next) => {
        res.append('X-Recruiting', config_1.default.get('application.securityTxt.hiring'));
        next();
    });
    /* Remove duplicate slashes from URL which allowed bypassing subsequent filters */
    app.use((req, res, next) => {
        req.url = req.url.replace(/[/]+/g, '/');
        next();
    });
    /* Increase request counter metric for every request */
    app.use(metrics.observeRequestMetricsMiddleware());
    /* Security Policy */
    const securityTxtExpiration = new Date();
    securityTxtExpiration.setFullYear(securityTxtExpiration.getFullYear() + 1);
    app.get(['/.well-known/security.txt', '/security.txt'], verify.accessControlChallenges());
    app.use(['/.well-known/security.txt', '/security.txt'], (0, express_security_txt_1.default)({
        contact: config_1.default.get('application.securityTxt.contact'),
        encryption: config_1.default.get('application.securityTxt.encryption'),
        acknowledgements: config_1.default.get('application.securityTxt.acknowledgements'),
        'Preferred-Languages': [...new Set(locales_json_1.default.map((locale) => locale.key.substr(0, 2)))].join(', '),
        hiring: config_1.default.get('application.securityTxt.hiring'),
        csaf: config_1.default.get('server.baseUrl') + config_1.default.get('application.securityTxt.csaf'),
        expires: securityTxtExpiration.toUTCString()
    }));
    /* robots.txt */
    app.use((0, express_robots_txt_1.default)({ UserAgent: '*', Disallow: '/ftp' }));
    /* Check for any URLs having been called that would be expected for challenge solving without cheating */
    app.use(antiCheat.checkForPreSolveInteractions());
    /* Checks for challenges solved by retrieving a file implicitly or explicitly */
    app.use('/assets/public/images/padding', verify.accessControlChallenges());
    app.use('/assets/public/images/products', verify.accessControlChallenges());
    app.use('/assets/public/images/uploads', verify.accessControlChallenges());
    app.use('/assets/i18n', verify.accessControlChallenges());
    /* Checks for challenges solved by abusing SSTi and SSRF bugs */
    app.use('/solve/challenges/server-side', verify.serverSideChallenges());
    /* Create middleware to change paths from the serve-index plugin from absolute to relative */
    const serveIndexMiddleware = (req, res, next) => {
        // eslint-disable-next-line @typescript-eslint/unbound-method
        const origEnd = res.end;
        // @ts-expect-error FIXME assignment broken due to seemingly void return value
        res.end = function () {
            if (arguments.length) {
                const reqPath = req.originalUrl.replace(/\?.*$/, '');
                // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
                const currentFolder = reqPath.split('/').pop();
                arguments[0] = arguments[0].replace(/a href="([^"]+?)"/gi, function (matchString, matchedUrl) {
                    let relativePath = node_path_1.default.relative(reqPath, matchedUrl);
                    if (relativePath === '') {
                        relativePath = currentFolder;
                    }
                    else if (!relativePath.startsWith('.') && currentFolder !== '') {
                        relativePath = currentFolder + '/' + relativePath;
                    }
                    else {
                        relativePath = relativePath.replace('..', '.');
                    }
                    return 'a href="' + relativePath + '"';
                });
            }
            // @ts-expect-error FIXME passed argument has wrong type
            origEnd.apply(this, arguments);
        };
        next();
    };
    // vuln-code-snippet start directoryListingChallenge accessLogDisclosureChallenge
    /* /ftp directory browsing and file download */ // vuln-code-snippet neutral-line directoryListingChallenge
    app.use('/ftp', serveIndexMiddleware, (0, serve_index_1.default)('ftp', { icons: true })); // vuln-code-snippet vuln-line directoryListingChallenge
    app.use('/ftp(?!/quarantine)/:file', (0, fileServer_1.servePublicFiles)()); // vuln-code-snippet vuln-line directoryListingChallenge
    app.use('/ftp/quarantine/:file', (0, quarantineServer_1.serveQuarantineFiles)()); // vuln-code-snippet neutral-line directoryListingChallenge
    app.use('/.well-known', serveIndexMiddleware, (0, serve_index_1.default)('.well-known', { icons: true, view: 'details' }));
    app.use('/.well-known', express_1.default.static('.well-known'));
    /* /encryptionkeys directory browsing */
    app.use('/encryptionkeys', serveIndexMiddleware, (0, serve_index_1.default)('encryptionkeys', { icons: true, view: 'details' }));
    app.use('/encryptionkeys/:file', (0, keyServer_1.serveKeyFiles)());
    /* /logs directory browsing */ // vuln-code-snippet neutral-line accessLogDisclosureChallenge
    app.use('/support/logs', serveIndexMiddleware, (0, serve_index_1.default)('logs', { icons: true, view: 'details' })); // vuln-code-snippet vuln-line accessLogDisclosureChallenge
    app.use('/support/logs', verify.accessControlChallenges()); // vuln-code-snippet hide-line
    app.use('/support/logs/:file', (0, logfileServer_1.serveLogFiles)()); // vuln-code-snippet vuln-line accessLogDisclosureChallenge
    /* Swagger documentation for B2B v2 endpoints */
    app.use('/api-docs', swagger_ui_express_1.default.serve, swagger_ui_express_1.default.setup(swaggerDocument));
    app.use(express_1.default.static(node_path_1.default.resolve('frontend/dist/frontend')));
    app.use((0, cookie_parser_1.default)('kekse'));
    // vuln-code-snippet end directoryListingChallenge accessLogDisclosureChallenge
    /* Configure and enable backend-side i18n */
    i18n_1.default.configure({
        locales: locales_json_1.default.map((locale) => locale.key),
        directory: node_path_1.default.resolve('i18n'),
        cookie: 'language',
        defaultLocale: 'en',
        autoReload: true
    });
    app.use(i18n_1.default.init);
    app.use(body_parser_1.default.urlencoded({ extended: true }));
    /* File Upload */
    app.post('/file-upload', uploadToMemory.single('file'), fileUpload_1.ensureFileIsPassed, metrics.observeFileUploadMetricsMiddleware(), fileUpload_1.checkUploadSize, fileUpload_1.checkFileType, fileUpload_1.handleZipFileUpload, fileUpload_1.handleXmlUpload, fileUpload_1.handleYamlUpload);
    app.post('/profile/image/file', uploadToMemory.single('file'), fileUpload_1.ensureFileIsPassed, metrics.observeFileUploadMetricsMiddleware(), (0, profileImageFileUpload_1.profileImageFileUpload)());
    app.post('/profile/image/url', uploadToMemory.single('file'), (0, profileImageUrlUpload_1.profileImageUrlUpload)());
    app.post('/rest/memories', uploadToDisk.single('image'), fileUpload_1.ensureFileIsPassed, security.appendUserId(), metrics.observeFileUploadMetricsMiddleware(), (0, memory_1.addMemory)());
    app.use(body_parser_1.default.text({ type: '*/*' }));
    app.use(function jsonParser(req, res, next) {
        // @ts-expect-error FIXME intentionally saving original request in this property
        req.rawBody = req.body;
        if (req.headers['content-type']?.includes('application/json')) {
            if (!req.body) {
                req.body = {};
            }
            if (req.body !== Object(req.body)) { // Expensive workaround for 500 errors during Frisby test run (see #640)
                req.body = JSON.parse(req.body);
            }
        }
        next();
    });
    /* HTTP request logging */
    const accessLogStream = (0, file_stream_rotator_1.getStream)({
        filename: node_path_1.default.resolve('logs/access.log.%DATE%'),
        date_format: 'YYYY-MM-DD',
        audit_file: 'logs/audit.json',
        frequency: 'daily',
        verbose: false,
        max_logs: '2d'
    });
    app.use((0, morgan_1.default)('combined', { stream: accessLogStream }));
    // vuln-code-snippet start resetPasswordMortyChallenge
    /* Rate limiting */
    app.enable('trust proxy');
    app.use('/rest/user/reset-password', (0, express_rate_limit_1.rateLimit)({
        windowMs: 5 * 60 * 1000,
        max: 100,
        keyGenerator({ headers, ip }) { return headers['X-Forwarded-For'] ?? ip; } // vuln-code-snippet vuln-line resetPasswordMortyChallenge
    }));
    // vuln-code-snippet end resetPasswordMortyChallenge
    // vuln-code-snippet start changeProductChallenge
    /** Authorization **/
    /* Checks on JWT in Authorization header */ // vuln-code-snippet hide-line
    app.use(verify.jwtChallenges()); // vuln-code-snippet hide-line
    /* Baskets: Unauthorized users are not allowed to access baskets */
    app.use('/rest/basket', security.isAuthorized(), security.appendUserId());
    /* BasketItems: API only accessible for authenticated users */
    app.use('/api/BasketItems', security.isAuthorized());
    app.use('/api/BasketItems/:id', security.isAuthorized());
    /* Feedbacks: GET allowed for feedback carousel, POST allowed in order to provide feedback without being logged in */
    app.use('/api/Feedbacks/:id', security.isAuthorized());
    /* Users: Only POST is allowed in order to register a new user */
    app.get('/api/Users', security.isAuthorized());
    app.route('/api/Users/:id')
        .get(security.isAuthorized())
        .put(security.denyAll())
        .delete(security.denyAll());
    /* Products: Only GET is allowed in order to view products */ // vuln-code-snippet neutral-line changeProductChallenge
    app.post('/api/Products', security.isAuthorized()); // vuln-code-snippet neutral-line changeProductChallenge
    // app.put('/api/Products/:id', security.isAuthorized()) // vuln-code-snippet vuln-line changeProductChallenge
    app.delete('/api/Products/:id', security.denyAll());
    /* Challenges: GET list of challenges allowed. Everything else forbidden entirely */
    app.post('/api/Challenges', security.denyAll());
    app.use('/api/Challenges/:id', security.denyAll());
    /* Complaints: POST and GET allowed when logged in only */
    app.get('/api/Complaints', security.isAuthorized());
    app.post('/api/Complaints', security.isAuthorized());
    app.use('/api/Complaints/:id', security.denyAll());
    /* Recycles: POST and GET allowed when logged in only */
    app.get('/api/Recycles', recycles.blockRecycleItems());
    app.post('/api/Recycles', security.isAuthorized());
    /* Challenge evaluation before finale takes over */
    app.get('/api/Recycles/:id', recycles.getRecycleItem());
    app.put('/api/Recycles/:id', security.denyAll());
    app.delete('/api/Recycles/:id', security.denyAll());
    /* SecurityQuestions: Only GET list of questions allowed. */
    app.post('/api/SecurityQuestions', security.denyAll());
    app.use('/api/SecurityQuestions/:id', security.denyAll());
    /* SecurityAnswers: Only POST of answer allowed. */
    app.get('/api/SecurityAnswers', security.denyAll());
    app.use('/api/SecurityAnswers/:id', security.denyAll());
    /* REST API */
    app.use('/rest/user/authentication-details', security.isAuthorized());
    app.use('/rest/basket/:id', security.isAuthorized());
    app.use('/rest/basket/:id/order', security.isAuthorized());
    /* Challenge evaluation before finale takes over */ // vuln-code-snippet hide-start
    app.post('/api/Feedbacks', verify.forgedFeedbackChallenge());
    /* Captcha verification before finale takes over */
    app.post('/api/Feedbacks', (0, captcha_1.verifyCaptcha)());
    /* Captcha Bypass challenge verification */
    app.post('/api/Feedbacks', verify.captchaBypassChallenge());
    /* User registration challenge verifications before finale takes over */
    app.post('/api/Users', (req, res, next) => {
        if (req.body.email !== undefined && req.body.password !== undefined && req.body.passwordRepeat !== undefined) {
            if (req.body.email.length !== 0 && req.body.password.length !== 0) {
                req.body.email = req.body.email.trim();
                req.body.password = req.body.password.trim();
                req.body.passwordRepeat = req.body.passwordRepeat.trim();
            }
            else {
                res.status(400).send(res.__('Invalid email/password cannot be empty'));
            }
        }
        next();
    });
    app.post('/api/Users', verify.registerAdminChallenge());
    app.post('/api/Users', verify.passwordRepeatChallenge()); // vuln-code-snippet hide-end
    app.post('/api/Users', verify.emptyUserRegistration());
    /* Unauthorized users are not allowed to access B2B API */
    app.use('/b2b/v2', security.isAuthorized());
    /* Check if the quantity is available in stock and limit per user not exceeded, then add item to basket */
    app.put('/api/BasketItems/:id', security.appendUserId(), basketItems.quantityCheckBeforeBasketItemUpdate());
    app.post('/api/BasketItems', security.appendUserId(), basketItems.quantityCheckBeforeBasketItemAddition(), basketItems.addBasketItem());
    /* Accounting users are allowed to check and update quantities */
    app.delete('/api/Quantitys/:id', security.denyAll());
    app.post('/api/Quantitys', security.denyAll());
    app.use('/api/Quantitys/:id', security.isAccounting(), (0, express_ipfilter_1.IpFilter)(['123.456.789'], { mode: 'allow' }));
    /* Feedbacks: Do not allow changes of existing feedback */
    app.put('/api/Feedbacks/:id', security.denyAll());
    /* PrivacyRequests: Only allowed for authenticated users */
    app.use('/api/PrivacyRequests', security.isAuthorized());
    app.use('/api/PrivacyRequests/:id', security.isAuthorized());
    /* PaymentMethodRequests: Only allowed for authenticated users */
    app.post('/api/Cards', security.appendUserId());
    app.get('/api/Cards', security.appendUserId(), payment.getPaymentMethods());
    app.put('/api/Cards/:id', security.denyAll());
    app.delete('/api/Cards/:id', security.appendUserId(), payment.delPaymentMethodById());
    app.get('/api/Cards/:id', security.appendUserId(), payment.getPaymentMethodById());
    /* PrivacyRequests: Only POST allowed for authenticated users */
    app.post('/api/PrivacyRequests', security.isAuthorized());
    app.get('/api/PrivacyRequests', security.denyAll());
    app.use('/api/PrivacyRequests/:id', security.denyAll());
    app.post('/api/Addresss', security.appendUserId());
    app.get('/api/Addresss', security.appendUserId(), address.getAddress());
    app.put('/api/Addresss/:id', security.appendUserId());
    app.delete('/api/Addresss/:id', security.appendUserId(), address.delAddressById());
    app.get('/api/Addresss/:id', security.appendUserId(), address.getAddressById());
    app.get('/api/Deliverys', delivery.getDeliveryMethods());
    app.get('/api/Deliverys/:id', delivery.getDeliveryMethod());
    // vuln-code-snippet end changeProductChallenge
    /* Verify the 2FA Token */
    app.post('/rest/2fa/verify', (0, express_rate_limit_1.rateLimit)({ windowMs: 5 * 60 * 1000, max: 100, validate: false }), twoFactorAuth.verify);
    /* Check 2FA Status for the current User */
    app.get('/rest/2fa/status', security.isAuthorized(), twoFactorAuth.status);
    /* Enable 2FA for the current User */
    app.post('/rest/2fa/setup', (0, express_rate_limit_1.rateLimit)({ windowMs: 5 * 60 * 1000, max: 100, validate: false }), security.isAuthorized(), twoFactorAuth.setup);
    /* Disable 2FA Status for the current User */
    app.post('/rest/2fa/disable', (0, express_rate_limit_1.rateLimit)({ windowMs: 5 * 60 * 1000, max: 100, validate: false }), security.isAuthorized(), twoFactorAuth.disable);
    /* Verifying DB related challenges can be postponed until the next request for challenges is coming via finale */
    app.use(verify.databaseRelatedChallenges());
    // vuln-code-snippet start registerAdminChallenge
    /* Generated API endpoints */
    finale.initialize({ app, sequelize: models_1.sequelize });
    const autoModels = [
        { name: 'User', exclude: ['password', 'totpSecret'], model: user_1.UserModel },
        { name: 'Product', exclude: [], model: product_1.ProductModel },
        { name: 'Feedback', exclude: [], model: feedback_1.FeedbackModel },
        { name: 'BasketItem', exclude: [], model: basketitem_1.BasketItemModel },
        { name: 'Challenge', exclude: [], model: challenge_1.ChallengeModel },
        { name: 'Complaint', exclude: [], model: complaint_1.ComplaintModel },
        { name: 'Recycle', exclude: [], model: recycle_1.RecycleModel },
        { name: 'SecurityQuestion', exclude: [], model: securityQuestion_1.SecurityQuestionModel },
        { name: 'SecurityAnswer', exclude: [], model: securityAnswer_1.SecurityAnswerModel },
        { name: 'Address', exclude: [], model: address_1.AddressModel },
        { name: 'PrivacyRequest', exclude: [], model: privacyRequests_1.PrivacyRequestModel },
        { name: 'Card', exclude: [], model: card_1.CardModel },
        { name: 'Quantity', exclude: [], model: quantity_1.QuantityModel }
    ];
    for (const { name, exclude, model } of autoModels) {
        const resource = finale.resource({
            model,
            endpoints: [`/api/${name}s`, `/api/${name}s/:id`],
            excludeAttributes: exclude,
            pagination: false
        });
        // create a wallet when a new user is registered using API
        if (name === 'User') { // vuln-code-snippet neutral-line registerAdminChallenge
            resource.create.send.before((req, res, context) => {
                wallet_1.WalletModel.create({ UserId: context.instance.id }).catch((err) => {
                    console.log(err);
                });
                return context.continue; // vuln-code-snippet neutral-line registerAdminChallenge
            }); // vuln-code-snippet neutral-line registerAdminChallenge
        } // vuln-code-snippet neutral-line registerAdminChallenge
        // vuln-code-snippet end registerAdminChallenge
        // translate challenge descriptions and hints on-the-fly
        if (name === 'Challenge') {
            resource.list.fetch.after((req, res, context) => {
                for (let i = 0; i < context.instance.length; i++) {
                    let description = context.instance[i].description;
                    if (utils.contains(description, '<em>(This challenge is <strong>')) {
                        const warning = description.substring(description.indexOf(' <em>(This challenge is <strong>'));
                        description = description.substring(0, description.indexOf(' <em>(This challenge is <strong>'));
                        context.instance[i].description = req.__(description) + req.__(warning);
                    }
                    else {
                        context.instance[i].description = req.__(description);
                    }
                    if (context.instance[i].hint) {
                        context.instance[i].hint = req.__(context.instance[i].hint);
                    }
                }
                return context.continue;
            });
            resource.read.send.before((req, res, context) => {
                context.instance.description = req.__(context.instance.description);
                if (context.instance.hint) {
                    context.instance.hint = req.__(context.instance.hint);
                }
                return context.continue;
            });
        }
        // translate security questions on-the-fly
        if (name === 'SecurityQuestion') {
            resource.list.fetch.after((req, res, context) => {
                for (let i = 0; i < context.instance.length; i++) {
                    context.instance[i].question = req.__(context.instance[i].question);
                }
                return context.continue;
            });
            resource.read.send.before((req, res, context) => {
                context.instance.question = req.__(context.instance.question);
                return context.continue;
            });
        }
        // translate product names and descriptions on-the-fly
        if (name === 'Product') {
            resource.list.fetch.after((req, res, context) => {
                for (let i = 0; i < context.instance.length; i++) {
                    context.instance[i].name = req.__(context.instance[i].name);
                    context.instance[i].description = req.__(context.instance[i].description);
                }
                return context.continue;
            });
            resource.read.send.before((req, res, context) => {
                context.instance.name = req.__(context.instance.name);
                context.instance.description = req.__(context.instance.description);
                return context.continue;
            });
        }
        // fix the api difference between finale (fka epilogue) and previously used sequlize-restful
        resource.all.send.before((req, res, context) => {
            context.instance = {
                status: 'success',
                data: context.instance
            };
            return context.continue;
        });
    }
    /* Custom Restful API */
    app.post('/rest/user/login', (0, login_1.login)());
    app.get('/rest/user/change-password', (0, changePassword_1.changePassword)());
    app.post('/rest/user/reset-password', (0, resetPassword_1.resetPassword)());
    app.get('/rest/user/security-question', (0, securityQuestion_2.securityQuestion)());
    app.get('/rest/user/whoami', security.updateAuthenticatedUsers(), (0, currentUser_1.retrieveLoggedInUser)());
    app.get('/rest/user/authentication-details', (0, authenticatedUsers_1.default)());
    app.get('/rest/products/search', (0, search_1.searchProducts)());
    app.get('/rest/basket/:id', (0, basket_1.retrieveBasket)());
    app.post('/rest/basket/:id/checkout', (0, order_1.placeOrder)());
    app.put('/rest/basket/:id/coupon/:coupon', (0, coupon_1.applyCoupon)());
    app.get('/rest/admin/application-version', (0, appVersion_1.retrieveAppVersion)());
    app.get('/rest/admin/application-configuration', (0, appConfiguration_1.retrieveAppConfiguration)());
    app.get('/rest/repeat-notification', (0, repeatNotification_1.repeatNotification)());
    app.get('/rest/continue-code', (0, continueCode_1.continueCode)());
    app.get('/rest/continue-code-findIt', (0, continueCode_1.continueCodeFindIt)());
    app.get('/rest/continue-code-fixIt', (0, continueCode_1.continueCodeFixIt)());
    app.put('/rest/continue-code-findIt/apply/:continueCode', restoreProgress.restoreProgressFindIt());
    app.put('/rest/continue-code-fixIt/apply/:continueCode', restoreProgress.restoreProgressFixIt());
    app.put('/rest/continue-code/apply/:continueCode', restoreProgress.restoreProgress());
    app.get('/rest/captcha', (0, captcha_1.captchas)());
    app.get('/rest/image-captcha', (0, imageCaptcha_1.imageCaptchas)());
    app.get('/rest/track-order/:id', (0, trackOrder_1.trackOrder)());
    app.get('/rest/country-mapping', (0, countryMapping_1.countryMapping)());
    app.get('/rest/saveLoginIp', (0, saveLoginIp_1.saveLoginIp)());
    app.post('/rest/user/data-export', security.appendUserId(), (0, imageCaptcha_1.verifyImageCaptcha)());
    app.post('/rest/user/data-export', security.appendUserId(), (0, dataExport_1.dataExport)());
    app.get('/rest/languages', (0, languages_1.getLanguageList)());
    app.get('/rest/order-history', (0, orderHistory_1.orderHistory)());
    app.get('/rest/order-history/orders', security.isAccounting(), (0, orderHistory_1.allOrders)());
    app.put('/rest/order-history/:id/delivery-status', security.isAccounting(), (0, orderHistory_1.toggleDeliveryStatus)());
    app.get('/rest/wallet/balance', security.appendUserId(), (0, wallet_2.getWalletBalance)());
    app.put('/rest/wallet/balance', security.appendUserId(), (0, wallet_2.addWalletBalance)());
    app.get('/rest/deluxe-membership', (0, deluxe_1.deluxeMembershipStatus)());
    app.post('/rest/deluxe-membership', security.appendUserId(), (0, deluxe_1.upgradeToDeluxe)());
    app.get('/rest/memories', (0, memory_1.getMemories)());
    app.get('/rest/chatbot/status', chatbot.status());
    app.post('/rest/chatbot/respond', chatbot.process());
    /* NoSQL API endpoints */
    app.get('/rest/products/:id/reviews', (0, showProductReviews_1.showProductReviews)());
    app.put('/rest/products/:id/reviews', (0, createProductReviews_1.createProductReviews)());
    app.patch('/rest/products/reviews', security.isAuthorized(), (0, updateProductReviews_1.updateProductReviews)());
    app.post('/rest/products/reviews', security.isAuthorized(), (0, likeProductReviews_1.likeProductReviews)());
    /* Web3 API endpoints */
    app.post('/rest/web3/submitKey', (0, checkKeys_1.checkKeys)());
    app.get('/rest/web3/nftUnlocked', (0, checkKeys_1.nftUnlocked)());
    app.get('/rest/web3/nftMintListen', (0, nftMint_1.nftMintListener)());
    app.post('/rest/web3/walletNFTVerify', (0, nftMint_1.walletNFTVerify)());
    app.post('/rest/web3/walletExploitAddress', (0, web3Wallet_1.contractExploitListener)());
    /* B2B Order API */
    app.post('/b2b/v2/orders', (0, b2bOrder_1.b2bOrder)());
    /* File Serving */
    app.get('/the/devs/are/so/funny/they/hid/an/easter/egg/within/the/easter/egg', (0, easterEgg_1.serveEasterEgg)());
    app.get('/this/page/is/hidden/behind/an/incredibly/high/paywall/that/could/only/be/unlocked/by/sending/1btc/to/us', (0, premiumReward_1.servePremiumContent)());
    app.get('/we/may/also/instruct/you/to/refuse/all/reasonably/necessary/responsibility', (0, privacyPolicyProof_1.servePrivacyPolicyProof)());
    /* Route for dataerasure page */
    app.use('/dataerasure', dataErasure_1.default);
    /* Route for redirects */
    app.get('/redirect', (0, redirect_1.performRedirect)());
    /* Routes for promotion video page */
    app.get('/promotion', (0, videoHandler_1.promotionVideo)());
    app.get('/video', (0, videoHandler_1.getVideo)());
    /* Routes for profile page */
    app.get('/profile', security.updateAuthenticatedUsers(), (0, userProfile_1.getUserProfile)());
    app.post('/profile', (0, updateUserProfile_1.updateUserProfile)());
    /* Route for vulnerable code snippets */
    app.get('/snippets/:challenge', (0, vulnCodeSnippet_1.serveCodeSnippet)());
    app.post('/snippets/verdict', (0, vulnCodeSnippet_1.checkVulnLines)());
    app.get('/snippets/fixes/:key', (0, vulnCodeFixes_1.serveCodeFixes)());
    app.post('/snippets/fixes', (0, vulnCodeFixes_1.checkCorrectFix)());
    app.use((0, angular_1.serveAngularClient)());
    /* Error Handling */
    app.use(verify.errorHandlingChallenge());
    app.use(errorhandler());
}).catch((err) => {
    console.error(err);
});
const uploadToMemory = (0, multer_1.default)({ storage: multer_1.default.memoryStorage(), limits: { fileSize: 200000 } });
const mimeTypeMap = {
    'image/png': 'png',
    'image/jpeg': 'jpg',
    'image/jpg': 'jpg'
};
const uploadToDisk = (0, multer_1.default)({
    storage: multer_1.default.diskStorage({
        destination: (req, file, cb) => {
            const isValid = mimeTypeMap[file.mimetype];
            let error = new Error('Invalid mime type');
            if (isValid) {
                error = null;
            }
            cb(error, node_path_1.default.resolve('frontend/dist/frontend/assets/public/images/uploads/'));
        },
        filename: (req, file, cb) => {
            const name = security.sanitizeFilename(file.originalname)
                .toLowerCase()
                .split(' ')
                .join('-');
            const ext = mimeTypeMap[file.mimetype];
            cb(null, name + '-' + Date.now() + '.' + ext);
        }
    })
});
const expectedModels = ['Address', 'Basket', 'BasketItem', 'Captcha', 'Card', 'Challenge', 'Complaint', 'Delivery', 'Feedback', 'ImageCaptcha', 'Memory', 'PrivacyRequestModel', 'Product', 'Quantity', 'Recycle', 'SecurityAnswer', 'SecurityQuestion', 'User', 'Wallet'];
while (!expectedModels.every(model => Object.keys(models_1.sequelize.models).includes(model))) {
    logger_1.default.info(`Entity models ${safe_1.default.bold(Object.keys(models_1.sequelize.models).length.toString())} of ${safe_1.default.bold(expectedModels.length.toString())} are initialized (${safe_1.default.yellow('WAITING')})`);
}
logger_1.default.info(`Entity models ${safe_1.default.bold(Object.keys(models_1.sequelize.models).length.toString())} of ${safe_1.default.bold(expectedModels.length.toString())} are initialized (${safe_1.default.green('OK')})`);
// vuln-code-snippet start exposedMetricsChallenge
/* Serve metrics */
let metricsUpdateLoop;
const Metrics = metrics.observeMetrics(); // vuln-code-snippet neutral-line exposedMetricsChallenge
app.get('/metrics', metrics.serveMetrics()); // vuln-code-snippet vuln-line exposedMetricsChallenge
errorhandler.title = `${config_1.default.get('application.name')} (Express ${utils.version('express')})`;
async function start(readyCallback) {
    const datacreatorEnd = startupGauge.startTimer({ task: 'datacreator' });
    await models_1.sequelize.sync({ force: true });
    await (0, datacreator_1.default)();
    datacreatorEnd();
    const port = process.env.PORT ?? config_1.default.get('server.port');
    process.env.BASE_PATH = process.env.BASE_PATH ?? config_1.default.get('server.basePath');
    metricsUpdateLoop = Metrics.updateLoop(); // vuln-code-snippet neutral-line exposedMetricsChallenge
    server.listen(port, () => {
        logger_1.default.info(safe_1.default.cyan(`Server listening on port ${safe_1.default.bold(`${port}`)}`));
        startupGauge.set({ task: 'ready' }, (Date.now() - startTime) / 1000);
        if (process.env.BASE_PATH !== '') {
            logger_1.default.info(safe_1.default.cyan(`Server using proxy base path ${safe_1.default.bold(`${process.env.BASE_PATH}`)} for redirects`));
        }
        (0, registerWebsocketEvents_1.default)(server);
        if (readyCallback) {
            readyCallback();
        }
    });
    void collectDurationPromise('customizeApplication', customizeApplication_1.default)(); // vuln-code-snippet hide-line
    void collectDurationPromise('customizeEasterEgg', customizeEasterEgg_1.default)(); // vuln-code-snippet hide-line
}
exports.start = start;
function close(exitCode) {
    if (server) {
        clearInterval(metricsUpdateLoop);
        server.close();
    }
    if (exitCode !== undefined) {
        process.exit(exitCode);
    }
}
exports.close = close;
// vuln-code-snippet end exposedMetricsChallenge
// stop server on sigint or sigterm signals
process.on('SIGINT', () => { close(0); });
process.on('SIGTERM', () => { close(0); });
//# sourceMappingURL=server.js.map