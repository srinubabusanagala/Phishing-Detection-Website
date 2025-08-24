"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.loadStaticSecurityQuestionsData = exports.loadStaticDeliveryData = exports.loadStaticChallengeData = exports.loadStaticUserData = exports.loadStaticData = void 0;
const node_path_1 = __importDefault(require("node:path"));
const promises_1 = require("node:fs/promises");
const js_yaml_1 = require("js-yaml");
const logger_1 = __importDefault(require("../lib/logger"));
async function loadStaticData(file) {
    const filePath = node_path_1.default.resolve('./data/static/' + file + '.yml');
    return await (0, promises_1.readFile)(filePath, 'utf8')
        .then(js_yaml_1.safeLoad)
        .catch(() => logger_1.default.error('Could not open file: "' + filePath + '"'));
}
exports.loadStaticData = loadStaticData;
async function loadStaticUserData() {
    return await loadStaticData('users');
}
exports.loadStaticUserData = loadStaticUserData;
async function loadStaticChallengeData() {
    return await loadStaticData('challenges');
}
exports.loadStaticChallengeData = loadStaticChallengeData;
async function loadStaticDeliveryData() {
    return await loadStaticData('deliveries');
}
exports.loadStaticDeliveryData = loadStaticDeliveryData;
async function loadStaticSecurityQuestionsData() {
    return await loadStaticData('securityQuestions');
}
exports.loadStaticSecurityQuestionsData = loadStaticSecurityQuestionsData;
//# sourceMappingURL=staticData.js.map