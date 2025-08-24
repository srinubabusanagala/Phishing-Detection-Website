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
exports.observeMetrics = exports.serveMetrics = exports.observeFileUploadMetricsMiddleware = exports.observeRequestMetricsMiddleware = void 0;
const vulnCodeSnippet_1 = require("./vulnCodeSnippet");
const challenge_1 = require("../models/challenge");
const user_1 = require("../models/user");
const wallet_1 = require("../models/wallet");
const feedback_1 = require("../models/feedback");
const complaint_1 = require("../models/complaint");
const sequelize_1 = require("sequelize");
const challengeUtils = __importStar(require("../lib/challengeUtils"));
const logger_1 = __importDefault(require("../lib/logger"));
const config_1 = __importDefault(require("config"));
const utils = __importStar(require("../lib/utils"));
const antiCheat_1 = require("../lib/antiCheat");
const accuracy = __importStar(require("../lib/accuracy"));
const mongodb_1 = require("../data/mongodb");
const datacache_1 = require("../data/datacache");
const Prometheus = __importStar(require("prom-client"));
const on_finished_1 = __importDefault(require("on-finished"));
const register = Prometheus.register;
const fileUploadsCountMetric = new Prometheus.Counter({
    name: 'file_uploads_count',
    help: 'Total number of successful file uploads grouped by file type.',
    labelNames: ['file_type']
});
const fileUploadErrorsMetric = new Prometheus.Counter({
    name: 'file_upload_errors',
    help: 'Total number of failed file uploads grouped by file type.',
    labelNames: ['file_type']
});
function observeRequestMetricsMiddleware() {
    const httpRequestsMetric = new Prometheus.Counter({
        name: 'http_requests_count',
        help: 'Total HTTP request count grouped by status code.',
        labelNames: ['status_code']
    });
    return (req, res, next) => {
        (0, on_finished_1.default)(res, () => {
            const statusCode = `${Math.floor(res.statusCode / 100)}XX`;
            httpRequestsMetric.labels(statusCode).inc();
        });
        next();
    };
}
exports.observeRequestMetricsMiddleware = observeRequestMetricsMiddleware;
function observeFileUploadMetricsMiddleware() {
    return ({ file }, res, next) => {
        (0, on_finished_1.default)(res, () => {
            if (file != null) {
                res.statusCode < 400 ? fileUploadsCountMetric.labels(file.mimetype).inc() : fileUploadErrorsMetric.labels(file.mimetype).inc();
            }
        });
        next();
    };
}
exports.observeFileUploadMetricsMiddleware = observeFileUploadMetricsMiddleware;
function serveMetrics() {
    return async (req, res, next) => {
        challengeUtils.solveIf(datacache_1.challenges.exposedMetricsChallenge, () => {
            const userAgent = req.headers['user-agent'] ?? '';
            const ignoredUserAgents = config_1.default.get('challenges.metricsIgnoredUserAgents');
            return !ignoredUserAgents.some((ignoredUserAgent) => userAgent.includes(ignoredUserAgent));
        });
        res.set('Content-Type', register.contentType);
        res.end(await register.metrics());
    };
}
exports.serveMetrics = serveMetrics;
function observeMetrics() {
    const app = config_1.default.get('application.customMetricsPrefix');
    Prometheus.collectDefaultMetrics({});
    register.setDefaultLabels({ app });
    const versionMetrics = new Prometheus.Gauge({
        name: `${app}_version_info`,
        help: `Release version of ${config_1.default.get('application.name')}.`,
        labelNames: ['version', 'major', 'minor', 'patch']
    });
    const challengeSolvedMetrics = new Prometheus.Gauge({
        name: `${app}_challenges_solved`,
        help: 'Number of solved challenges grouped by difficulty and category.',
        labelNames: ['difficulty', 'category']
    });
    const challengeTotalMetrics = new Prometheus.Gauge({
        name: `${app}_challenges_total`,
        help: 'Total number of challenges grouped by difficulty and category.',
        labelNames: ['difficulty', 'category']
    });
    const codingChallengesProgressMetrics = new Prometheus.Gauge({
        name: `${app}_coding_challenges_progress`,
        help: 'Number of coding challenges grouped by progression phase.',
        labelNames: ['phase']
    });
    const cheatScoreMetrics = new Prometheus.Gauge({
        name: `${app}_cheat_score`,
        help: 'Overall probability that any hacking or coding challenges were solved by cheating.'
    });
    const accuracyMetrics = new Prometheus.Gauge({
        name: `${app}_coding_challenges_accuracy`,
        help: 'Overall accuracy while solving coding challenges grouped by phase.',
        labelNames: ['phase']
    });
    const orderMetrics = new Prometheus.Gauge({
        name: `${app}_orders_placed_total`,
        help: `Number of orders placed in ${config_1.default.get('application.name')}.`
    });
    const userMetrics = new Prometheus.Gauge({
        name: `${app}_users_registered`,
        help: 'Number of registered users grouped by customer type.',
        labelNames: ['type']
    });
    const userTotalMetrics = new Prometheus.Gauge({
        name: `${app}_users_registered_total`,
        help: 'Total number of registered users.'
    });
    const walletMetrics = new Prometheus.Gauge({
        name: `${app}_wallet_balance_total`,
        help: 'Total balance of all users\' digital wallets.'
    });
    const interactionsMetrics = new Prometheus.Gauge({
        name: `${app}_user_social_interactions`,
        help: 'Number of social interactions with users grouped by type.',
        labelNames: ['type']
    });
    const updateLoop = () => setInterval(() => {
        try {
            const version = utils.version();
            const { major, minor, patch } = version.match(/(?<major>\d+).(?<minor>\d+).(?<patch>\d+)/).groups;
            versionMetrics.set({ version, major, minor, patch }, 1);
            const challengeStatuses = new Map();
            const challengeCount = new Map();
            for (const { difficulty, category, solved } of Object.values(datacache_1.challenges)) {
                const key = `${difficulty}:${category}`;
                // Increment by one if solved, when not solved increment by 0. This ensures that even unsolved challenges are set to , instead of not being set at all
                challengeStatuses.set(key, (challengeStatuses.get(key) || 0) + (solved ? 1 : 0));
                challengeCount.set(key, (challengeCount.get(key) || 0) + 1);
            }
            for (const key of challengeStatuses.keys()) {
                const [difficulty, category] = key.split(':', 2);
                challengeSolvedMetrics.set({ difficulty, category }, challengeStatuses.get(key));
                challengeTotalMetrics.set({ difficulty, category }, challengeCount.get(key));
            }
            void (0, vulnCodeSnippet_1.retrieveChallengesWithCodeSnippet)().then(challenges => {
                challenge_1.ChallengeModel.count({ where: { codingChallengeStatus: { [sequelize_1.Op.eq]: 1 } } }).then((count) => {
                    codingChallengesProgressMetrics.set({ phase: 'find it' }, count);
                }).catch(() => {
                    throw new Error('Unable to retrieve and count such challenges. Please try again');
                });
                challenge_1.ChallengeModel.count({ where: { codingChallengeStatus: { [sequelize_1.Op.eq]: 2 } } }).then((count) => {
                    codingChallengesProgressMetrics.set({ phase: 'fix it' }, count);
                }).catch((_) => {
                    throw new Error('Unable to retrieve and count such challenges. Please try again');
                });
                challenge_1.ChallengeModel.count({ where: { codingChallengeStatus: { [sequelize_1.Op.ne]: 0 } } }).then((count) => {
                    codingChallengesProgressMetrics.set({ phase: 'unsolved' }, challenges.length - count);
                }).catch((_) => {
                    throw new Error('Unable to retrieve and count such challenges. Please try again');
                });
            });
            cheatScoreMetrics.set((0, antiCheat_1.totalCheatScore)());
            accuracyMetrics.set({ phase: 'find it' }, accuracy.totalFindItAccuracy());
            accuracyMetrics.set({ phase: 'fix it' }, accuracy.totalFixItAccuracy());
            mongodb_1.ordersCollection.count({}).then((orderCount) => {
                if (orderCount)
                    orderMetrics.set(orderCount);
            });
            mongodb_1.reviewsCollection.count({}).then((reviewCount) => {
                if (reviewCount)
                    interactionsMetrics.set({ type: 'review' }, reviewCount);
            });
            void user_1.UserModel.count({ where: { role: { [sequelize_1.Op.eq]: 'customer' } } }).then((count) => {
                if (count)
                    userMetrics.set({ type: 'standard' }, count);
            });
            void user_1.UserModel.count({ where: { role: { [sequelize_1.Op.eq]: 'deluxe' } } }).then((count) => {
                if (count)
                    userMetrics.set({ type: 'deluxe' }, count);
            });
            void user_1.UserModel.count().then((count) => {
                if (count)
                    userTotalMetrics.set(count);
            });
            void wallet_1.WalletModel.sum('balance').then((totalBalance) => {
                if (totalBalance)
                    walletMetrics.set(totalBalance);
            });
            void feedback_1.FeedbackModel.count().then((count) => {
                if (count)
                    interactionsMetrics.set({ type: 'feedback' }, count);
            });
            void complaint_1.ComplaintModel.count().then((count) => {
                if (count)
                    interactionsMetrics.set({ type: 'complaint' }, count);
            });
        }
        catch (e) {
            logger_1.default.warn('Error during metrics update loop: + ' + utils.getErrorMessage(e));
        }
    }, 5000);
    return {
        register,
        updateLoop
    };
}
exports.observeMetrics = observeMetrics;
//# sourceMappingURL=metrics.js.map