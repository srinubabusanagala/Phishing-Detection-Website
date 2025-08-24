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
/* jslint node: true */
const address_1 = require("../models/address");
const basket_1 = require("../models/basket");
const basketitem_1 = require("../models/basketitem");
const card_1 = require("../models/card");
const challenge_1 = require("../models/challenge");
const complaint_1 = require("../models/complaint");
const delivery_1 = require("../models/delivery");
const feedback_1 = require("../models/feedback");
const memory_1 = require("../models/memory");
const product_1 = require("../models/product");
const quantity_1 = require("../models/quantity");
const recycle_1 = require("../models/recycle");
const securityAnswer_1 = require("../models/securityAnswer");
const securityQuestion_1 = require("../models/securityQuestion");
const user_1 = require("../models/user");
const wallet_1 = require("../models/wallet");
const logger_1 = __importDefault(require("../lib/logger"));
const codingChallenges_1 = require("../lib/codingChallenges");
const config_1 = __importDefault(require("config"));
const utils = __importStar(require("../lib/utils"));
const staticData_1 = require("./staticData");
const mongodb_1 = require("./mongodb");
const html_entities_1 = require("html-entities");
const datacache = __importStar(require("./datacache"));
const security = __importStar(require("../lib/insecurity"));
// @ts-expect-error FIXME due to non-existing type definitions for replace
const replace_1 = __importDefault(require("replace"));
const entities = new html_entities_1.AllHtmlEntities();
exports.default = async () => {
    const creators = [
        createSecurityQuestions,
        createUsers,
        createChallenges,
        createRandomFakeUsers,
        createProducts,
        createBaskets,
        createBasketItems,
        createAnonymousFeedback,
        createComplaints,
        createRecycleItem,
        createOrders,
        createQuantity,
        createWallet,
        createDeliveryMethods,
        createMemories,
        prepareFilesystem
    ];
    for (const creator of creators) {
        await creator();
    }
};
async function createChallenges() {
    const showHints = config_1.default.get('challenges.showHints');
    const showMitigations = config_1.default.get('challenges.showMitigations');
    const challenges = await (0, staticData_1.loadStaticChallengeData)();
    const codeChallenges = await (0, codingChallenges_1.getCodeChallenges)();
    const challengeKeysWithCodeChallenges = [...codeChallenges.keys()];
    await Promise.all(challenges.map(async ({ name, category, description, difficulty, hint, hintUrl, mitigationUrl, key, disabledEnv, tutorial, tags }) => {
        // todo(@J12934) change this to use a proper challenge model or something
        // eslint-disable-next-line @typescript-eslint/consistent-type-assertions
        const { enabled: isChallengeEnabled, disabledBecause } = utils.getChallengeEnablementStatus({ disabledEnv: disabledEnv?.join(';') ?? '' });
        description = description.replace('juice-sh.op', config_1.default.get('application.domain'));
        description = description.replace('&lt;iframe width=&quot;100%&quot; height=&quot;166&quot; scrolling=&quot;no&quot; frameborder=&quot;no&quot; allow=&quot;autoplay&quot; src=&quot;https://w.soundcloud.com/player/?url=https%3A//api.soundcloud.com/tracks/771984076&amp;color=%23ff5500&amp;auto_play=true&amp;hide_related=false&amp;show_comments=true&amp;show_user=true&amp;show_reposts=false&amp;show_teaser=true&quot;&gt;&lt;/iframe&gt;', entities.encode(config_1.default.get('challenges.xssBonusPayload')));
        hint = hint.replace(/OWASP Juice Shop's/, `${config_1.default.get('application.name')}'s`);
        const hasCodingChallenge = challengeKeysWithCodeChallenges.includes(key);
        if (hasCodingChallenge) {
            tags = tags ? [...tags, 'With Coding Challenge'] : ['With Coding Challenge'];
        }
        try {
            datacache.challenges[key] = await challenge_1.ChallengeModel.create({
                key,
                name,
                category,
                tags: (tags != null) ? tags.join(',') : undefined,
                // todo(@J12934) currently missing the 'not available' text. Needs changes to the model and utils functions
                description: isChallengeEnabled ? description : (description + ' <em>(This challenge is <strong>potentially harmful</strong> on ' + disabledBecause + '!)</em>'),
                difficulty,
                solved: false,
                hint: showHints ? hint : null,
                hintUrl: showHints ? hintUrl : null,
                mitigationUrl: showMitigations ? mitigationUrl : null,
                disabledEnv: disabledBecause,
                tutorialOrder: (tutorial != null) ? tutorial.order : null,
                codingChallengeStatus: 0,
                hasCodingChallenge
            });
        }
        catch (err) {
            logger_1.default.error(`Could not insert Challenge ${name}: ${utils.getErrorMessage(err)}`);
        }
    }));
}
async function createUsers() {
    const users = await (0, staticData_1.loadStaticUserData)();
    await Promise.all(users.map(async ({ username, email, password, customDomain, key, role, deletedFlag, profileImage, securityQuestion, feedback, address, card, totpSecret, lastLoginIp = '' }) => {
        try {
            const completeEmail = customDomain ? email : `${email}@${config_1.default.get('application.domain')}`;
            const user = await user_1.UserModel.create({
                username,
                email: completeEmail,
                password,
                role,
                deluxeToken: role === security.roles.deluxe ? security.deluxeToken(completeEmail) : '',
                profileImage: `assets/public/images/uploads/${profileImage ?? (role === security.roles.admin ? 'defaultAdmin.png' : 'default.svg')}`,
                totpSecret,
                lastLoginIp
            });
            datacache.users[key] = user;
            if (securityQuestion != null)
                await createSecurityAnswer(user.id, securityQuestion.id, securityQuestion.answer);
            if (feedback != null)
                await createFeedback(user.id, feedback.comment, feedback.rating, user.email);
            if (deletedFlag)
                await deleteUser(user.id);
            if (address != null)
                await createAddresses(user.id, address);
            if (card != null)
                await createCards(user.id, card);
        }
        catch (err) {
            logger_1.default.error(`Could not insert User ${key}: ${utils.getErrorMessage(err)}`);
        }
    }));
}
async function createWallet() {
    const users = await (0, staticData_1.loadStaticUserData)();
    return await Promise.all(users.map(async (user, index) => {
        return await wallet_1.WalletModel.create({
            UserId: index + 1,
            balance: user.walletBalance ?? 0
        }).catch((err) => {
            logger_1.default.error(`Could not create wallet: ${utils.getErrorMessage(err)}`);
        });
    }));
}
async function createDeliveryMethods() {
    const deliveries = await (0, staticData_1.loadStaticDeliveryData)();
    await Promise.all(deliveries.map(async ({ name, price, deluxePrice, eta, icon }) => {
        try {
            await delivery_1.DeliveryModel.create({
                name,
                price,
                deluxePrice,
                eta,
                icon
            });
        }
        catch (err) {
            logger_1.default.error(`Could not insert Delivery Method: ${utils.getErrorMessage(err)}`);
        }
    }));
}
async function createAddresses(UserId, addresses) {
    return await Promise.all(addresses.map(async (address) => {
        return await address_1.AddressModel.create({
            UserId,
            country: address.country,
            fullName: address.fullName,
            mobileNum: address.mobileNum,
            zipCode: address.zipCode,
            streetAddress: address.streetAddress,
            city: address.city,
            state: address.state ? address.state : null
        }).catch((err) => {
            logger_1.default.error(`Could not create address: ${utils.getErrorMessage(err)}`);
        });
    }));
}
async function createCards(UserId, cards) {
    return await Promise.all(cards.map(async (card) => {
        return await card_1.CardModel.create({
            UserId,
            fullName: card.fullName,
            cardNum: Number(card.cardNum),
            expMonth: card.expMonth,
            expYear: card.expYear
        }).catch((err) => {
            logger_1.default.error(`Could not create card: ${utils.getErrorMessage(err)}`);
        });
    }));
}
async function deleteUser(userId) {
    return await user_1.UserModel.destroy({ where: { id: userId } }).catch((err) => {
        logger_1.default.error(`Could not perform soft delete for the user ${userId}: ${utils.getErrorMessage(err)}`);
    });
}
async function deleteProduct(productId) {
    return await product_1.ProductModel.destroy({ where: { id: productId } }).catch((err) => {
        logger_1.default.error(`Could not perform soft delete for the product ${productId}: ${utils.getErrorMessage(err)}`);
    });
}
async function createRandomFakeUsers() {
    function getGeneratedRandomFakeUserEmail() {
        const randomDomain = makeRandomString(4).toLowerCase() + '.' + makeRandomString(2).toLowerCase();
        return makeRandomString(5).toLowerCase() + '@' + randomDomain;
    }
    function makeRandomString(length) {
        let text = '';
        const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        for (let i = 0; i < length; i++) {
            text += possible.charAt(Math.floor(Math.random() * possible.length));
        }
        return text;
    }
    return await Promise.all(new Array(config_1.default.get('application.numberOfRandomFakeUsers')).fill(0).map(async () => await user_1.UserModel.create({
        email: getGeneratedRandomFakeUserEmail(),
        password: makeRandomString(5)
    })));
}
async function createQuantity() {
    return await Promise.all(config_1.default.get('products').map(async (product, index) => {
        return await quantity_1.QuantityModel.create({
            ProductId: index + 1,
            quantity: product.quantity ?? Math.floor(Math.random() * 70 + 30),
            limitPerUser: product.limitPerUser ?? null
        }).catch((err) => {
            logger_1.default.error(`Could not create quantity: ${utils.getErrorMessage(err)}`);
        });
    }));
}
async function createMemories() {
    const memories = [
        memory_1.MemoryModel.create({
            imagePath: 'assets/public/images/uploads/ᓚᘏᗢ-#zatschi-#whoneedsfourlegs-1572600969477.jpg',
            caption: '😼 #zatschi #whoneedsfourlegs',
            UserId: datacache.users.bjoernOwasp.id
        }).catch((err) => {
            logger_1.default.error(`Could not create memory: ${utils.getErrorMessage(err)}`);
        }),
        ...structuredClone(config_1.default.get('memories')).map(async (memory) => {
            let tmpImageFileName = memory.image;
            if (utils.isUrl(memory.image)) {
                const imageUrl = memory.image;
                tmpImageFileName = utils.extractFilename(memory.image);
                void utils.downloadToFile(imageUrl, 'frontend/dist/frontend/assets/public/images/uploads/' + tmpImageFileName);
            }
            if (memory.geoStalkingMetaSecurityQuestion && memory.geoStalkingMetaSecurityAnswer) {
                await createSecurityAnswer(datacache.users.john.id, memory.geoStalkingMetaSecurityQuestion, memory.geoStalkingMetaSecurityAnswer);
                memory.user = 'john';
            }
            if (memory.geoStalkingVisualSecurityQuestion && memory.geoStalkingVisualSecurityAnswer) {
                await createSecurityAnswer(datacache.users.emma.id, memory.geoStalkingVisualSecurityQuestion, memory.geoStalkingVisualSecurityAnswer);
                memory.user = 'emma';
            }
            if (!memory.user) {
                logger_1.default.warn(`Could not find user for memory ${memory.caption}!`);
                return;
            }
            const userIdOfMemory = datacache.users[memory.user].id.valueOf() ?? null;
            if (!userIdOfMemory) {
                logger_1.default.warn(`Could not find saved user for memory ${memory.caption}!`);
                return;
            }
            return await memory_1.MemoryModel.create({
                imagePath: 'assets/public/images/uploads/' + tmpImageFileName,
                caption: memory.caption,
                UserId: userIdOfMemory
            }).catch((err) => {
                logger_1.default.error(`Could not create memory: ${utils.getErrorMessage(err)}`);
            });
        })
    ];
    return await Promise.all(memories);
}
async function createProducts() {
    const products = structuredClone(config_1.default.get('products')).map((product) => {
        product.price = product.price ?? Math.floor(Math.random() * 9 + 1);
        product.deluxePrice = product.deluxePrice ?? product.price;
        product.description = product.description || 'Lorem ipsum dolor sit amet, consectetuer adipiscing elit.';
        // set default image values
        product.image = product.image ?? 'undefined.png';
        if (utils.isUrl(product.image)) {
            const imageUrl = product.image;
            product.image = utils.extractFilename(product.image);
            void utils.downloadToFile(imageUrl, 'frontend/dist/frontend/assets/public/images/products/' + product.image);
        }
        return product;
    });
    // add Challenge specific information
    const christmasChallengeProduct = products.find(({ useForChristmasSpecialChallenge }) => useForChristmasSpecialChallenge);
    const pastebinLeakChallengeProduct = products.find(({ keywordsForPastebinDataLeakChallenge }) => keywordsForPastebinDataLeakChallenge);
    const tamperingChallengeProduct = products.find(({ urlForProductTamperingChallenge }) => urlForProductTamperingChallenge);
    const blueprintRetrievalChallengeProduct = products.find(({ fileForRetrieveBlueprintChallenge }) => fileForRetrieveBlueprintChallenge);
    if (christmasChallengeProduct) {
        christmasChallengeProduct.description += ' (Seasonal special offer! Limited availability!)';
        christmasChallengeProduct.deletedDate = '2014-12-27 00:00:00.000 +00:00';
    }
    if (tamperingChallengeProduct) {
        tamperingChallengeProduct.description += ' <a href="' + tamperingChallengeProduct.urlForProductTamperingChallenge + '" target="_blank">More...</a>';
        delete tamperingChallengeProduct.deletedDate;
    }
    if (pastebinLeakChallengeProduct) {
        pastebinLeakChallengeProduct.description += ' (This product is unsafe! We plan to remove it from the stock!)';
        pastebinLeakChallengeProduct.deletedDate = '2019-02-1 00:00:00.000 +00:00';
    }
    if (blueprintRetrievalChallengeProduct) {
        // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
        let blueprint = blueprintRetrievalChallengeProduct.fileForRetrieveBlueprintChallenge;
        if (utils.isUrl(blueprint)) {
            const blueprintUrl = blueprint;
            blueprint = utils.extractFilename(blueprint);
            await utils.downloadToFile(blueprintUrl, 'frontend/dist/frontend/assets/public/images/products/' + blueprint);
        }
        datacache.setRetrieveBlueprintChallengeFile(blueprint);
    }
    return await Promise.all(products.map(async ({ reviews = [], useForChristmasSpecialChallenge = false, urlForProductTamperingChallenge = false, fileForRetrieveBlueprintChallenge = false, deletedDate = false, ...product }) => await product_1.ProductModel.create({
        name: product.name,
        description: product.description,
        price: product.price,
        deluxePrice: product.deluxePrice ?? product.price,
        image: product.image
    }).catch((err) => {
        logger_1.default.error(`Could not insert Product ${product.name}: ${utils.getErrorMessage(err)}`);
    }).then(async (persistedProduct) => {
        if (persistedProduct != null) {
            if (useForChristmasSpecialChallenge) {
                datacache.products.christmasSpecial = persistedProduct;
            }
            if (urlForProductTamperingChallenge) {
                datacache.products.osaft = persistedProduct;
                await datacache.challenges.changeProductChallenge.update({
                    description: customizeChangeProductChallenge(datacache.challenges.changeProductChallenge.description, config_1.default.get('challenges.overwriteUrlForProductTamperingChallenge'), persistedProduct)
                });
            }
            if (fileForRetrieveBlueprintChallenge && datacache.challenges.retrieveBlueprintChallenge.hint !== null) {
                await datacache.challenges.retrieveBlueprintChallenge.update({
                    hint: customizeRetrieveBlueprintChallenge(datacache.challenges.retrieveBlueprintChallenge.hint, persistedProduct)
                });
            }
            if (deletedDate)
                void deleteProduct(persistedProduct.id); // TODO Rename into "isDeleted" or "deletedFlag" in config for v14.x release
        }
        else {
            throw new Error('No persisted product found!');
        }
        return persistedProduct;
    })
        .then(async ({ id }) => await Promise.all(reviews.map(({ text, author }) => mongodb_1.reviewsCollection.insert({
        message: text,
        author: datacache.users[author].email,
        product: id,
        likesCount: 0,
        likedBy: []
    }).catch((err) => {
        logger_1.default.error(`Could not insert Product Review ${text}: ${utils.getErrorMessage(err)}`);
    }))))));
    function customizeChangeProductChallenge(description, customUrl, customProduct) {
        let customDescription = description.replace(/OWASP SSL Advanced Forensic Tool \(O-Saft\)/g, customProduct.name);
        customDescription = customDescription.replace('https://owasp.slack.com', customUrl);
        return customDescription;
    }
    function customizeRetrieveBlueprintChallenge(hint, customProduct) {
        return hint.replace(/OWASP Juice Shop Logo \(3D-printed\)/g, customProduct.name);
    }
}
async function createBaskets() {
    const baskets = [
        { UserId: 1 },
        { UserId: 2 },
        { UserId: 3 },
        { UserId: 11 },
        { UserId: 16 }
    ];
    return await Promise.all(baskets.map(async (basket) => {
        return await basket_1.BasketModel.create({
            UserId: basket.UserId
        }).catch((err) => {
            logger_1.default.error(`Could not insert Basket for UserId ${basket.UserId}: ${utils.getErrorMessage(err)}`);
        });
    }));
}
async function createBasketItems() {
    const basketItems = [
        {
            BasketId: 1,
            ProductId: 1,
            quantity: 2
        },
        {
            BasketId: 1,
            ProductId: 2,
            quantity: 3
        },
        {
            BasketId: 1,
            ProductId: 3,
            quantity: 1
        },
        {
            BasketId: 2,
            ProductId: 4,
            quantity: 2
        },
        {
            BasketId: 3,
            ProductId: 4,
            quantity: 1
        },
        {
            BasketId: 4,
            ProductId: 4,
            quantity: 2
        },
        {
            BasketId: 5,
            ProductId: 3,
            quantity: 5
        },
        {
            BasketId: 5,
            ProductId: 4,
            quantity: 2
        }
    ];
    return await Promise.all(basketItems.map(async (basketItem) => {
        return await basketitem_1.BasketItemModel.create(basketItem).catch((err) => {
            logger_1.default.error(`Could not insert BasketItem for BasketId ${basketItem.BasketId}: ${utils.getErrorMessage(err)}`);
        });
    }));
}
async function createAnonymousFeedback() {
    const feedbacks = [
        {
            comment: 'Incompetent customer support! Can\'t even upload photo of broken purchase!<br><em>Support Team: Sorry, only order confirmation PDFs can be attached to complaints!</em>',
            rating: 2
        },
        {
            comment: 'This is <b>the</b> store for awesome stuff of all kinds!',
            rating: 4
        },
        {
            comment: 'Never gonna buy anywhere else from now on! Thanks for the great service!',
            rating: 4
        },
        {
            comment: 'Keep up the good work!',
            rating: 3
        }
    ];
    return await Promise.all(feedbacks.map(async (feedback) => await createFeedback(null, feedback.comment, feedback.rating)));
}
async function createFeedback(UserId, comment, rating, author) {
    const authoredComment = author ? `${comment} (***${author.slice(3)})` : `${comment} (anonymous)`;
    return await feedback_1.FeedbackModel.create({ UserId, comment: authoredComment, rating }).catch((err) => {
        logger_1.default.error(`Could not insert Feedback ${authoredComment} mapped to UserId ${UserId}: ${utils.getErrorMessage(err)}`);
    });
}
async function createComplaints() {
    return await complaint_1.ComplaintModel.create({
        UserId: 3,
        message: 'I\'ll build my own eCommerce business! With Black Jack! And Hookers!'
    }).catch((err) => {
        logger_1.default.error(`Could not insert Complaint: ${utils.getErrorMessage(err)}`);
    });
}
async function createRecycleItem() {
    const recycles = [
        {
            UserId: 2,
            quantity: 800,
            AddressId: 4,
            date: '2270-01-17',
            isPickup: true
        },
        {
            UserId: 3,
            quantity: 1320,
            AddressId: 6,
            date: '2006-01-14',
            isPickup: true
        },
        {
            UserId: 4,
            quantity: 120,
            AddressId: 1,
            date: '2018-04-16',
            isPickup: true
        },
        {
            UserId: 1,
            quantity: 300,
            AddressId: 3,
            date: '2018-01-17',
            isPickup: true
        },
        {
            UserId: 4,
            quantity: 350,
            AddressId: 1,
            date: '2018-03-17',
            isPickup: true
        },
        {
            UserId: 3,
            quantity: 200,
            AddressId: 6,
            date: '2018-07-17',
            isPickup: true
        },
        {
            UserId: 4,
            quantity: 140,
            AddressId: 1,
            date: '2018-03-19',
            isPickup: true
        },
        {
            UserId: 1,
            quantity: 150,
            AddressId: 3,
            date: '2018-05-12',
            isPickup: true
        },
        {
            UserId: 16,
            quantity: 500,
            AddressId: 2,
            date: '2019-02-18',
            isPickup: true
        }
    ];
    return await Promise.all(recycles.map(async (recycle) => await createRecycle(recycle)));
}
async function createRecycle(data) {
    return await recycle_1.RecycleModel.create({
        UserId: data.UserId,
        AddressId: data.AddressId,
        quantity: data.quantity,
        isPickup: data.isPickup,
        date: data.date
    }).catch((err) => {
        logger_1.default.error(`Could not insert Recycling Model: ${utils.getErrorMessage(err)}`);
    });
}
async function createSecurityQuestions() {
    const questions = await (0, staticData_1.loadStaticSecurityQuestionsData)();
    await Promise.all(questions.map(async ({ question }) => {
        try {
            await securityQuestion_1.SecurityQuestionModel.create({ question });
        }
        catch (err) {
            logger_1.default.error(`Could not insert SecurityQuestion ${question}: ${utils.getErrorMessage(err)}`);
        }
    }));
}
async function createSecurityAnswer(UserId, SecurityQuestionId, answer) {
    return await securityAnswer_1.SecurityAnswerModel.create({ SecurityQuestionId, UserId, answer }).catch((err) => {
        logger_1.default.error(`Could not insert SecurityAnswer ${answer} mapped to UserId ${UserId}: ${utils.getErrorMessage(err)}`);
    });
}
async function createOrders() {
    const products = config_1.default.get('products');
    const basket1Products = [
        {
            quantity: 3,
            id: products[0].id,
            name: products[0].name,
            price: products[0].price,
            total: products[0].price * 3,
            bonus: Math.round(products[0].price / 10) * 3
        },
        {
            quantity: 1,
            id: products[1].id,
            name: products[1].name,
            price: products[1].price,
            total: products[1].price * 1,
            bonus: Math.round(products[1].price / 10) * 1
        }
    ];
    const basket2Products = [
        {
            quantity: 3,
            id: products[2].id,
            name: products[2].name,
            price: products[2].price,
            total: products[2].price * 3,
            bonus: Math.round(products[2].price / 10) * 3
        }
    ];
    const basket3Products = [
        {
            quantity: 3,
            id: products[0].id,
            name: products[0].name,
            price: products[0].price,
            total: products[0].price * 3,
            bonus: Math.round(products[0].price / 10) * 3
        },
        {
            quantity: 5,
            id: products[3].id,
            name: products[3].name,
            price: products[3].price,
            total: products[3].price * 5,
            bonus: Math.round(products[3].price / 10) * 5
        }
    ];
    const adminEmail = 'admin@' + config_1.default.get('application.domain');
    const orders = [
        {
            orderId: security.hash(adminEmail).slice(0, 4) + '-' + utils.randomHexString(16),
            email: (adminEmail.replace(/[aeiou]/gi, '*')),
            totalPrice: basket1Products[0].total + basket1Products[1].total,
            bonus: basket1Products[0].bonus + basket1Products[1].bonus,
            products: basket1Products,
            eta: Math.floor((Math.random() * 5) + 1).toString(),
            delivered: false
        },
        {
            orderId: security.hash(adminEmail).slice(0, 4) + '-' + utils.randomHexString(16),
            email: (adminEmail.replace(/[aeiou]/gi, '*')),
            totalPrice: basket2Products[0].total,
            bonus: basket2Products[0].bonus,
            products: basket2Products,
            eta: '0',
            delivered: true
        },
        {
            orderId: security.hash('demo').slice(0, 4) + '-' + utils.randomHexString(16),
            email: 'd*m*',
            totalPrice: basket3Products[0].total + basket3Products[1].total,
            bonus: basket3Products[0].bonus + basket3Products[1].bonus,
            products: basket3Products,
            eta: '0',
            delivered: true
        }
    ];
    return await Promise.all(orders.map(({ orderId, email, totalPrice, bonus, products, eta, delivered }) => mongodb_1.ordersCollection.insert({
        orderId,
        email,
        totalPrice,
        bonus,
        products,
        eta,
        delivered
    }).catch((err) => {
        logger_1.default.error(`Could not insert Order ${orderId}: ${utils.getErrorMessage(err)}`);
    })));
}
async function prepareFilesystem() {
    (0, replace_1.default)({
        regex: 'http://localhost:3000',
        replacement: config_1.default.get('server.baseUrl'),
        paths: ['.well-known/csaf/provider-metadata.json'],
        recursive: true,
        silent: true
    });
}
//# sourceMappingURL=datacreator.js.map