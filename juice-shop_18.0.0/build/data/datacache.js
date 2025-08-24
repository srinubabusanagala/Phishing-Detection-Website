"use strict";
/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.setRetrieveBlueprintChallengeFile = exports.retrieveBlueprintChallengeFile = exports.notifications = exports.complaints = exports.basketItems = exports.baskets = exports.feedback = exports.products = exports.users = exports.challenges = void 0;
/* jslint node: true */
exports.challenges = {}; // this is a hack to have the challenge key non-nullable, but on init it is null.
exports.users = {};
exports.products = {};
exports.feedback = {};
exports.baskets = {};
exports.basketItems = {};
exports.complaints = {};
exports.notifications = [];
exports.retrieveBlueprintChallengeFile = null;
function setRetrieveBlueprintChallengeFile(retrieveBlueprintChallengeFileArg) {
    exports.retrieveBlueprintChallengeFile = retrieveBlueprintChallengeFileArg;
}
exports.setRetrieveBlueprintChallengeFile = setRetrieveBlueprintChallengeFile;
//# sourceMappingURL=datacache.js.map