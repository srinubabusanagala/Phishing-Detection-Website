"use strict";
/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.checkForIllogicalCombos = exports.checkUniqueSpecialOnMemories = exports.checkSpecialMemoriesHaveNoUserAssociated = exports.checkUnambiguousMandatorySpecialMemories = exports.checkMinimumRequiredNumberOfMemories = exports.checkUniqueSpecialOnProducts = exports.checkNecessaryExtraKeysOnSpecialProducts = exports.checkUnambiguousMandatorySpecialProducts = exports.checkMinimumRequiredNumberOfProducts = exports.checkYamlSchema = void 0;
const node_path_1 = __importDefault(require("node:path"));
const config_1 = __importDefault(require("config"));
const node_process_1 = __importDefault(require("node:process"));
const safe_1 = __importDefault(require("colors/safe"));
// @ts-expect-error FIXME due to non-existing type definitions for yaml-schema-validator
const src_1 = __importDefault(require("yaml-schema-validator/src"));
const logger_1 = __importDefault(require("../logger"));
const specialProducts = [
    { name: '"Christmas Special" challenge product', key: 'useForChristmasSpecialChallenge' },
    { name: '"Product Tampering" challenge product', key: 'urlForProductTamperingChallenge' },
    { name: '"Retrieve Blueprint" challenge product', key: 'fileForRetrieveBlueprintChallenge', extra: { key: 'exifForBlueprintChallenge', name: 'list of EXIF metadata properties' } },
    { name: '"Leaked Unsafe Product" challenge product', key: 'keywordsForPastebinDataLeakChallenge' }
];
const specialMemories = [
    { name: '"Meta Geo Stalking" challenge memory', user: 'john', keys: ['geoStalkingMetaSecurityQuestion', 'geoStalkingMetaSecurityAnswer'] },
    { name: '"Visual Geo Stalking" challenge memory', user: 'emma', keys: ['geoStalkingVisualSecurityQuestion', 'geoStalkingVisualSecurityAnswer'] }
];
const validateConfig = async ({ products, memories, exitOnFailure = true }) => {
    products = products ?? config_1.default.get('products') ?? [];
    memories = memories ?? config_1.default.get('memories') ?? [];
    let success = true;
    success = (0, exports.checkYamlSchema)() && success;
    success = (0, exports.checkMinimumRequiredNumberOfProducts)(products) && success;
    success = (0, exports.checkUnambiguousMandatorySpecialProducts)(products) && success;
    success = (0, exports.checkUniqueSpecialOnProducts)(products) && success;
    success = (0, exports.checkNecessaryExtraKeysOnSpecialProducts)(products) && success;
    success = (0, exports.checkMinimumRequiredNumberOfMemories)(memories) && success;
    success = (0, exports.checkUnambiguousMandatorySpecialMemories)(memories) && success;
    success = (0, exports.checkUniqueSpecialOnMemories)(memories) && success;
    success = (0, exports.checkSpecialMemoriesHaveNoUserAssociated)(memories) && success;
    success = (0, exports.checkForIllogicalCombos)() && success;
    if (success) {
        logger_1.default.info(`Configuration ${safe_1.default.bold(node_process_1.default.env.NODE_ENV ?? 'default')} validated (${safe_1.default.green('OK')})`);
    }
    else {
        logger_1.default.warn(`Configuration ${safe_1.default.bold(node_process_1.default.env.NODE_ENV ?? 'default')} validated (${safe_1.default.red('NOT OK')})`);
        logger_1.default.warn(`Visit ${safe_1.default.yellow('https://pwning.owasp-juice.shop/companion-guide/latest/part4/customization.html#_yaml_configuration_file')} for the configuration schema definition.`);
        if (exitOnFailure) {
            logger_1.default.error(safe_1.default.red('Exiting due to configuration errors!'));
            node_process_1.default.exit(1);
        }
    }
    return success;
};
const checkYamlSchema = (configuration = config_1.default.util.toObject()) => {
    let success = true;
    const schemaErrors = (0, src_1.default)(configuration, { schemaPath: node_path_1.default.resolve('config.schema.yml'), logLevel: 'none' });
    if (schemaErrors.length !== 0) {
        logger_1.default.warn(`Config schema validation failed with ${schemaErrors.length} errors (${safe_1.default.red('NOT OK')})`);
        schemaErrors.forEach(({ path, message }) => {
            logger_1.default.warn(`${path}:${safe_1.default.red(message.substr(message.indexOf(path) + path.length))}`);
        });
        success = false;
    }
    return success;
};
exports.checkYamlSchema = checkYamlSchema;
const checkMinimumRequiredNumberOfProducts = (products) => {
    let success = true;
    if (products.length < 4) {
        logger_1.default.warn(`Only ${products.length} products are configured but at least four are required (${safe_1.default.red('NOT OK')})`);
        success = false;
    }
    return success;
};
exports.checkMinimumRequiredNumberOfProducts = checkMinimumRequiredNumberOfProducts;
const checkUnambiguousMandatorySpecialProducts = (products) => {
    let success = true;
    specialProducts.forEach(({ name, key }) => {
        // @ts-expect-error FIXME Ignoring any type issue on purpose
        const matchingProducts = products.filter((product) => product[key]);
        if (matchingProducts.length === 0) {
            logger_1.default.warn(`No product is configured as ${safe_1.default.italic(name)} but one is required (${safe_1.default.red('NOT OK')})`);
            success = false;
        }
        else if (matchingProducts.length > 1) {
            logger_1.default.warn(`${matchingProducts.length} products are configured as ${safe_1.default.italic(name)} but only one is allowed (${safe_1.default.red('NOT OK')})`);
            success = false;
        }
    });
    return success;
};
exports.checkUnambiguousMandatorySpecialProducts = checkUnambiguousMandatorySpecialProducts;
const checkNecessaryExtraKeysOnSpecialProducts = (products) => {
    let success = true;
    specialProducts.forEach(({ name, key, extra = {} }) => {
        // @ts-expect-error FIXME implicit any type issue
        const matchingProducts = products.filter((product) => product[key]);
        // @ts-expect-error FIXME implicit any type issue
        if (extra.key && matchingProducts.length === 1 && !matchingProducts[0][extra.key]) {
            logger_1.default.warn(`Product ${safe_1.default.italic(matchingProducts[0].name)} configured as ${safe_1.default.italic(name)} does't contain necessary ${safe_1.default.italic(`${extra.name}`)} (${safe_1.default.red('NOT OK')})`);
            success = false;
        }
    });
    return success;
};
exports.checkNecessaryExtraKeysOnSpecialProducts = checkNecessaryExtraKeysOnSpecialProducts;
const checkUniqueSpecialOnProducts = (products) => {
    let success = true;
    products.forEach((product) => {
        // @ts-expect-error FIXME any type issue
        const appliedSpecials = specialProducts.filter(({ key }) => product[key]);
        if (appliedSpecials.length > 1) {
            logger_1.default.warn(`Product ${safe_1.default.italic(product.name)} is used as ${appliedSpecials.map(({ name }) => `${safe_1.default.italic(name)}`).join(' and ')} but can only be used for one challenge (${safe_1.default.red('NOT OK')})`);
            success = false;
        }
    });
    return success;
};
exports.checkUniqueSpecialOnProducts = checkUniqueSpecialOnProducts;
const checkMinimumRequiredNumberOfMemories = (memories) => {
    let success = true;
    if (memories.length < 2) {
        logger_1.default.warn(`Only ${memories.length} memories are configured but at least two are required (${safe_1.default.red('NOT OK')})`);
        success = false;
    }
    return success;
};
exports.checkMinimumRequiredNumberOfMemories = checkMinimumRequiredNumberOfMemories;
const checkUnambiguousMandatorySpecialMemories = (memories) => {
    let success = true;
    specialMemories.forEach(({ name, keys }) => {
        const matchingMemories = memories.filter((memory) => memory[keys[0]] && memory[keys[1]]);
        if (matchingMemories.length === 0) {
            logger_1.default.warn(`No memory is configured as ${safe_1.default.italic(name)} but one is required (${safe_1.default.red('NOT OK')})`);
            success = false;
        }
        else if (matchingMemories.length > 1) {
            logger_1.default.warn(`${matchingMemories.length} memories are configured as ${safe_1.default.italic(name)} but only one is allowed (${safe_1.default.red('NOT OK')})`);
            success = false;
        }
    });
    return success;
};
exports.checkUnambiguousMandatorySpecialMemories = checkUnambiguousMandatorySpecialMemories;
const checkSpecialMemoriesHaveNoUserAssociated = (memories) => {
    let success = true;
    specialMemories.forEach(({ name, user, keys }) => {
        const matchingMemories = memories.filter((memory) => memory[keys[0]] && memory[keys[1]] && memory.user && memory.user !== user);
        if (matchingMemories.length > 0) {
            logger_1.default.warn(`Memory configured as ${safe_1.default.italic(name)} must belong to user ${safe_1.default.italic(user)} but was linked to ${safe_1.default.italic(matchingMemories[0].user ?? 'unknown')} user (${safe_1.default.red('NOT OK')})`);
            success = false;
        }
    });
    return success;
};
exports.checkSpecialMemoriesHaveNoUserAssociated = checkSpecialMemoriesHaveNoUserAssociated;
const checkUniqueSpecialOnMemories = (memories) => {
    let success = true;
    memories.forEach((memory) => {
        const appliedSpecials = specialMemories.filter(({ keys }) => memory[keys[0]] && memory[keys[1]]);
        if (appliedSpecials.length > 1) {
            logger_1.default.warn(`Memory ${safe_1.default.italic(memory.caption)} is used as ${appliedSpecials.map(({ name }) => `${safe_1.default.italic(name)}`).join(' and ')} but can only be used for one challenge (${safe_1.default.red('NOT OK')})`);
            success = false;
        }
    });
    return success;
};
exports.checkUniqueSpecialOnMemories = checkUniqueSpecialOnMemories;
const checkForIllogicalCombos = (configuration = config_1.default.util.toObject()) => {
    let success = true;
    if (configuration.challenges.restrictToTutorialsFirst && !configuration.hackingInstructor.isEnabled) {
        logger_1.default.warn(`Restricted tutorial mode is enabled while Hacking Instructor is disabled (${safe_1.default.red('NOT OK')})`);
        success = false;
    }
    if (configuration.ctf.showFlagsInNotifications && !configuration.challenges.showSolvedNotifications) {
        logger_1.default.warn(`CTF flags are enabled while challenge solved notifications are disabled (${safe_1.default.red('NOT OK')})`);
        success = false;
    }
    if (['name', 'flag', 'both'].includes(configuration.ctf.showCountryDetailsInNotifications) && !configuration.ctf.showFlagsInNotifications) {
        logger_1.default.warn(`CTF country mappings for FBCTF are enabled while CTF flags are disabled (${safe_1.default.red('NOT OK')})`);
        success = false;
    }
    return success;
};
exports.checkForIllogicalCombos = checkForIllogicalCombos;
exports.default = validateConfig;
//# sourceMappingURL=validateConfig.js.map