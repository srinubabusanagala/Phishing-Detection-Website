"use strict";
/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const node_fs_1 = __importDefault(require("node:fs"));
const chai_1 = __importDefault(require("chai"));
const node_path_1 = __importDefault(require("node:path"));
const util_1 = require("util");
const js_yaml_1 = require("js-yaml");
const sinon_chai_1 = __importDefault(require("sinon-chai"));
const expect = chai_1.default.expect;
chai_1.default.use(sinon_chai_1.default);
const readFile = (0, util_1.promisify)(node_fs_1.default.readFile);
const loadYamlFile = async (filename) => {
    const contents = await readFile(filename, { encoding: 'utf8' });
    return (0, js_yaml_1.safeLoad)(contents);
};
describe('challengeCountryMapping', () => {
    let challenges;
    let countryMapping;
    before(async () => {
        challenges = await loadYamlFile(node_path_1.default.resolve('data/static/challenges.yml'));
        countryMapping = (await loadYamlFile(node_path_1.default.resolve('config/fbctf.yml')))?.ctf?.countryMapping;
    });
    it('should have a country mapping for every challenge', async () => {
        for (const { key } of challenges) {
            expect(countryMapping, `Challenge "${key}" does not have a country mapping.`).to.have.property(key);
        }
    });
    it('should have unique country codes in every mapping', async () => {
        const countryCodeCounts = {};
        for (const key of Object.keys(countryMapping)) {
            const { code } = countryMapping[key];
            if (!Object.prototype.hasOwnProperty.call(countryCodeCounts, code)) {
                countryCodeCounts[code] = 0;
            }
            countryCodeCounts[code]++;
        }
        for (const key of Object.keys(countryCodeCounts)) {
            const count = countryCodeCounts[key];
            expect(count, `Country "${key}" is used for multiple country mappings.`).to.equal(1);
        }
    });
});
//# sourceMappingURL=challengeCountryMappingSpec.js.map