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
const cypress_1 = require("cypress");
const security = __importStar(require("./lib/insecurity"));
const config_1 = __importDefault(require("config"));
const utils = __importStar(require("./lib/utils"));
const otplib = __importStar(require("otplib"));
exports.default = (0, cypress_1.defineConfig)({
    projectId: '3hrkhu',
    defaultCommandTimeout: 10000,
    retries: {
        runMode: 2
    },
    e2e: {
        baseUrl: 'http://localhost:3000',
        specPattern: 'test/cypress/e2e/**.spec.ts',
        downloadsFolder: 'test/cypress/downloads',
        fixturesFolder: false,
        supportFile: 'test/cypress/support/e2e.ts',
        setupNodeEvents(on) {
            on('task', {
                GenerateCoupon(discount) {
                    return security.generateCoupon(discount);
                },
                GetBlueprint() {
                    for (const product of config_1.default.get('products')) {
                        if (product.fileForRetrieveBlueprintChallenge) {
                            const blueprint = product.fileForRetrieveBlueprintChallenge;
                            return blueprint;
                        }
                    }
                },
                GetChristmasProduct() {
                    return config_1.default.get('products').filter((product) => product.useForChristmasSpecialChallenge)[0];
                },
                GetCouponIntent() {
                    const trainingData = require(`data/chatbot/${utils.extractFilename(config_1.default.get('application.chatBot.trainingData'))}`);
                    const couponIntent = trainingData.data.filter((data) => data.intent === 'queries.couponCode')[0];
                    return couponIntent;
                },
                GetFromMemories(property) {
                    for (const memory of config_1.default.get('memories')) {
                        if (memory[property]) {
                            return memory[property];
                        }
                    }
                },
                GetFromConfig(variable) {
                    return config_1.default.get(variable);
                },
                GetOverwriteUrl() {
                    return config_1.default.get('challenges.overwriteUrlForProductTamperingChallenge');
                },
                GetPastebinLeakProduct() {
                    return config_1.default.get('products').filter((product) => product.keywordsForPastebinDataLeakChallenge)[0];
                },
                GetTamperingProductId() {
                    const products = config_1.default.get('products');
                    for (let i = 0; i < products.length; i++) {
                        if (products[i].urlForProductTamperingChallenge) {
                            return i + 1;
                        }
                    }
                },
                GenerateAuthenticator(inputString) {
                    return otplib.authenticator.generate(inputString);
                },
                toISO8601() {
                    const date = new Date();
                    return utils.toISO8601(date);
                },
                isDocker() {
                    return utils.isDocker();
                },
                isWindows() {
                    return utils.isWindows();
                }
            });
        }
    }
});
//# sourceMappingURL=cypress.config.js.map