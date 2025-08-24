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
const chai_1 = __importDefault(require("chai"));
const sinon_chai_1 = __importDefault(require("sinon-chai"));
const validateConfig_1 = __importStar(require("../../lib/startup/validateConfig"));
const expect = chai_1.default.expect;
chai_1.default.use(sinon_chai_1.default);
describe('configValidation', () => {
    const COMMON_PRODUCT = { price: 1, description: 'foo', image: 'bar.jpg' };
    describe('checkUnambiguousMandatorySpecialProducts', () => {
        it('should accept a valid config', () => {
            const products = [
                {
                    ...COMMON_PRODUCT,
                    name: 'Apple Juice',
                    useForChristmasSpecialChallenge: true
                },
                {
                    ...COMMON_PRODUCT,
                    name: 'Orange Juice',
                    urlForProductTamperingChallenge: 'foobar'
                },
                {
                    ...COMMON_PRODUCT,
                    name: 'Melon Juice',
                    fileForRetrieveBlueprintChallenge: 'foobar',
                    exifForBlueprintChallenge: ['OpenSCAD']
                },
                {
                    ...COMMON_PRODUCT,
                    name: 'Rippertuer Special Juice',
                    keywordsForPastebinDataLeakChallenge: ['bla', 'blubb']
                }
            ];
            expect((0, validateConfig_1.checkUnambiguousMandatorySpecialProducts)(products)).to.equal(true);
        });
        it('should fail if multiple products are configured for the same challenge', () => {
            const products = [
                {
                    ...COMMON_PRODUCT,
                    name: 'Apple Juice',
                    useForChristmasSpecialChallenge: true
                },
                {
                    ...COMMON_PRODUCT,
                    name: 'Melon Bike',
                    useForChristmasSpecialChallenge: true
                },
                {
                    ...COMMON_PRODUCT,
                    name: 'Orange Juice',
                    urlForProductTamperingChallenge: 'foobar'
                },
                {
                    ...COMMON_PRODUCT,
                    name: 'Melon Juice',
                    fileForRetrieveBlueprintChallenge: 'foobar',
                    exifForBlueprintChallenge: ['OpenSCAD']
                }
            ];
            expect((0, validateConfig_1.checkUnambiguousMandatorySpecialProducts)(products)).to.equal(false);
        });
        it('should fail if a required challenge product is missing', () => {
            const products = [
                {
                    ...COMMON_PRODUCT,
                    name: 'Apple Juice',
                    useForChristmasSpecialChallenge: true
                },
                {
                    ...COMMON_PRODUCT,
                    name: 'Orange Juice',
                    urlForProductTamperingChallenge: 'foobar'
                }
            ];
            expect((0, validateConfig_1.checkUnambiguousMandatorySpecialProducts)(products)).to.equal(false);
        });
    });
    describe('checkNecessaryExtraKeysOnSpecialProducts', () => {
        it('should accept a valid config', () => {
            const products = [
                {
                    ...COMMON_PRODUCT,
                    name: 'Apple Juice',
                    useForChristmasSpecialChallenge: true
                },
                {
                    ...COMMON_PRODUCT,
                    name: 'Orange Juice',
                    urlForProductTamperingChallenge: 'foobar'
                },
                {
                    ...COMMON_PRODUCT,
                    name: 'Melon Juice',
                    fileForRetrieveBlueprintChallenge: 'foobar',
                    exifForBlueprintChallenge: ['OpenSCAD']
                },
                {
                    ...COMMON_PRODUCT,
                    name: 'Rippertuer Special Juice',
                    keywordsForPastebinDataLeakChallenge: ['bla', 'blubb']
                }
            ];
            expect((0, validateConfig_1.checkNecessaryExtraKeysOnSpecialProducts)(products)).to.equal(true);
        });
        it('should fail if product has no exifForBlueprintChallenge', () => {
            const products = [
                {
                    ...COMMON_PRODUCT,
                    name: 'Apple Juice',
                    useForChristmasSpecialChallenge: true
                },
                {
                    ...COMMON_PRODUCT,
                    name: 'Orange Juice',
                    urlForProductTamperingChallenge: 'foobar'
                },
                {
                    ...COMMON_PRODUCT,
                    name: 'Melon Juice',
                    fileForRetrieveBlueprintChallenge: 'foobar'
                },
                {
                    ...COMMON_PRODUCT,
                    name: 'Rippertuer Special Juice',
                    keywordsForPastebinDataLeakChallenge: ['bla', 'blubb']
                }
            ];
            expect((0, validateConfig_1.checkNecessaryExtraKeysOnSpecialProducts)(products)).to.equal(false);
        });
    });
    describe('checkUniqueSpecialOnProducts', () => {
        it('should accept a valid config', () => {
            const products = [
                {
                    ...COMMON_PRODUCT,
                    name: 'Apple Juice',
                    useForChristmasSpecialChallenge: true
                },
                {
                    ...COMMON_PRODUCT,
                    name: 'Orange Juice',
                    urlForProductTamperingChallenge: 'foobar'
                },
                {
                    ...COMMON_PRODUCT,
                    name: 'Melon Juice',
                    fileForRetrieveBlueprintChallenge: 'foobar',
                    exifForBlueprintChallenge: ['OpenSCAD']
                },
                {
                    ...COMMON_PRODUCT,
                    name: 'Rippertuer Special Juice',
                    keywordsForPastebinDataLeakChallenge: ['bla', 'blubb']
                }
            ];
            expect((0, validateConfig_1.checkUniqueSpecialOnProducts)(products)).to.equal(true);
        });
        it('should fail if a product is configured for multiple challenges', () => {
            const products = [
                {
                    ...COMMON_PRODUCT,
                    name: 'Apple Juice',
                    useForChristmasSpecialChallenge: true,
                    urlForProductTamperingChallenge: 'foobar'
                }
            ];
            expect((0, validateConfig_1.checkUniqueSpecialOnProducts)(products)).to.equal(false);
        });
    });
    describe('checkMinimumRequiredNumberOfProducts', () => {
        it('should accept a valid config', () => {
            const products = [
                {
                    ...COMMON_PRODUCT,
                    name: 'Apple Juice'
                },
                {
                    ...COMMON_PRODUCT,
                    name: 'Orange Juice'
                },
                {
                    ...COMMON_PRODUCT,
                    name: 'Melon Juice'
                },
                {
                    ...COMMON_PRODUCT,
                    name: 'Rippertuer Special Juice'
                }
            ];
            expect((0, validateConfig_1.checkMinimumRequiredNumberOfProducts)(products)).to.equal(true);
        });
        it('should fail if less than 4 products are configured', () => {
            const products = [
                {
                    ...COMMON_PRODUCT,
                    name: 'Apple Juice'
                },
                {
                    ...COMMON_PRODUCT,
                    name: 'Orange Juice'
                },
                {
                    ...COMMON_PRODUCT,
                    name: 'Melon Juice'
                }
            ];
            expect((0, validateConfig_1.checkMinimumRequiredNumberOfProducts)(products)).to.equal(false);
        });
    });
    describe('checkUnambiguousMandatorySpecialMemories', () => {
        it('should accept a valid config', () => {
            const memories = [
                {
                    image: 'bla.png',
                    caption: 'Bla',
                    geoStalkingMetaSecurityQuestion: 42,
                    geoStalkingMetaSecurityAnswer: 'foobar'
                },
                {
                    image: 'blubb.png',
                    caption: 'Blubb',
                    geoStalkingVisualSecurityQuestion: 43,
                    geoStalkingVisualSecurityAnswer: 'barfoo'
                }
            ];
            expect((0, validateConfig_1.checkUnambiguousMandatorySpecialMemories)(memories)).to.equal(true);
        });
        it('should fail if multiple memories are configured for the same challenge', () => {
            const memories = [
                {
                    image: 'bla.png',
                    caption: 'Bla',
                    geoStalkingMetaSecurityQuestion: 42,
                    geoStalkingMetaSecurityAnswer: 'foobar'
                },
                {
                    image: 'blubb.png',
                    caption: 'Blubb',
                    geoStalkingVisualSecurityQuestion: 43,
                    geoStalkingVisualSecurityAnswer: 'barfoo'
                },
                {
                    image: 'lalala.png',
                    caption: 'Lalala',
                    geoStalkingMetaSecurityQuestion: 46,
                    geoStalkingMetaSecurityAnswer: 'foobarfoo'
                }
            ];
            expect((0, validateConfig_1.checkUnambiguousMandatorySpecialMemories)(memories)).to.equal(false);
        });
        it('should fail if a required challenge memory is missing', () => {
            const memories = [
                {
                    image: 'bla.png',
                    caption: 'Bla',
                    geoStalkingMetaSecurityQuestion: 42,
                    geoStalkingMetaSecurityAnswer: 'foobar'
                }
            ];
            expect((0, validateConfig_1.checkUnambiguousMandatorySpecialMemories)(memories)).to.equal(false);
        });
        it('should fail if memories have mixed up the required challenge keys', () => {
            const memories = [
                {
                    image: 'bla.png',
                    caption: 'Bla',
                    geoStalkingMetaSecurityQuestion: 42,
                    geoStalkingVisualSecurityAnswer: 'foobar'
                },
                {
                    image: 'blubb.png',
                    caption: 'Blubb',
                    geoStalkingVisualSecurityQuestion: 43,
                    geoStalkingMetaSecurityAnswer: 'barfoo'
                }
            ];
            expect((0, validateConfig_1.checkUnambiguousMandatorySpecialMemories)(memories)).to.equal(false);
        });
    });
    describe('checkThatThereIsOnlyOneMemoryPerSpecial', () => {
        it('should accept a valid config', () => {
            const memories = [
                {
                    image: 'bla.png',
                    caption: 'Bla',
                    geoStalkingMetaSecurityQuestion: 42,
                    geoStalkingMetaSecurityAnswer: 'foobar'
                },
                {
                    image: 'blubb.png',
                    caption: 'Blubb',
                    geoStalkingVisualSecurityQuestion: 43,
                    geoStalkingVisualSecurityAnswer: 'barfoo'
                }
            ];
            expect((0, validateConfig_1.checkUniqueSpecialOnMemories)(memories)).to.equal(true);
        });
        it('should fail if a memory is configured for multiple challenges', () => {
            const memories = [
                {
                    image: 'bla.png',
                    caption: 'Bla',
                    geoStalkingMetaSecurityQuestion: 42,
                    geoStalkingMetaSecurityAnswer: 'foobar',
                    geoStalkingVisualSecurityQuestion: 43,
                    geoStalkingVisualSecurityAnswer: 'barfoo'
                }
            ];
            expect((0, validateConfig_1.checkUniqueSpecialOnMemories)(memories)).to.equal(false);
        });
    });
    describe('checkSpecialMemoriesHaveNoUserAssociated', () => {
        it('should accept a valid config', () => {
            const memories = [
                {
                    image: 'bla.png',
                    caption: 'Bla',
                    geoStalkingMetaSecurityQuestion: 42,
                    geoStalkingMetaSecurityAnswer: 'foobar'
                },
                {
                    image: 'blubb.png',
                    caption: 'Blubb',
                    geoStalkingVisualSecurityQuestion: 43,
                    geoStalkingVisualSecurityAnswer: 'barfoo'
                }
            ];
            expect((0, validateConfig_1.checkSpecialMemoriesHaveNoUserAssociated)(memories)).to.equal(true);
        });
        it('should accept a config where the default users are associated', () => {
            const memories = [
                {
                    user: 'john',
                    image: 'bla.png',
                    caption: 'Bla',
                    geoStalkingMetaSecurityQuestion: 42,
                    geoStalkingMetaSecurityAnswer: 'foobar'
                },
                {
                    user: 'emma',
                    image: 'blubb.png',
                    caption: 'Blubb',
                    geoStalkingVisualSecurityQuestion: 43,
                    geoStalkingVisualSecurityAnswer: 'barfoo'
                }
            ];
            expect((0, validateConfig_1.checkSpecialMemoriesHaveNoUserAssociated)(memories)).to.equal(true);
        });
        it('should fail if a memory is linked to another user', () => {
            const memories = [
                {
                    user: 'admin',
                    image: 'bla.png',
                    caption: 'Bla',
                    geoStalkingMetaSecurityQuestion: 42,
                    geoStalkingMetaSecurityAnswer: 'foobar'
                }
            ];
            expect((0, validateConfig_1.checkSpecialMemoriesHaveNoUserAssociated)(memories)).to.equal(false);
        });
    });
    describe('checkMinimumRequiredNumberOfMemories', () => {
        it('should accept a valid config', () => {
            const memories = [
                {
                    image: 'bla.png',
                    caption: 'Bla',
                    user: 'admin'
                },
                {
                    image: 'blubb.png',
                    caption: 'Blubb',
                    user: 'bjoern'
                }
            ];
            expect((0, validateConfig_1.checkMinimumRequiredNumberOfMemories)(memories)).to.equal(true);
        });
        it('should fail if less than 2 memories are configured', () => {
            const memories = [
                {
                    image: 'bla.png',
                    caption: 'Bla',
                    user: 'admin'
                }
            ];
            expect((0, validateConfig_1.checkMinimumRequiredNumberOfMemories)(memories)).to.equal(false);
        });
    });
    it(`should accept the active config from config/${process.env.NODE_ENV}.yml`, async () => {
        expect(await (0, validateConfig_1.default)({ exitOnFailure: false })).to.equal(true);
    });
    it('should fail if the config is invalid', async () => {
        expect(await (0, validateConfig_1.default)({ products: [], exitOnFailure: false })).to.equal(false);
    });
    it('should accept a config with valid schema', () => {
        const config = {
            application: {
                domain: 'juice-b.ox',
                name: 'OWASP Juice Box',
                welcomeBanner: {
                    showOnFirstStart: false
                }
            },
            hackingInstructor: {
                avatarImage: 'juicyEvilWasp.png'
            }
        };
        expect((0, validateConfig_1.checkYamlSchema)(config)).to.equal(true);
    });
    it('should fail for a config with schema errors', () => {
        const config = {
            application: {
                domain: 42,
                id: 'OWASP Juice Box',
                welcomeBanner: {
                    showOnFirstStart: 'yes'
                }
            },
            hackingInstructor: {
                avatarImage: true
            }
        };
        expect((0, validateConfig_1.checkYamlSchema)(config)).to.equal(false);
    });
});
//# sourceMappingURL=configValidationSpec.js.map