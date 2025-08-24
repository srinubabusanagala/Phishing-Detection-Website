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
const config_1 = __importDefault(require("config"));
const utils = __importStar(require("../utils"));
// @ts-expect-error FIXME due to non-existing type definitions for replace
const replace_1 = __importDefault(require("replace"));
const customizeEasterEgg = async () => {
    if (config_1.default.has('application.easterEggPlanet.overlayMap')) {
        let overlay = config_1.default.get('application.easterEggPlanet.overlayMap');
        if (utils.isUrl(overlay)) {
            const overlayPath = overlay;
            overlay = utils.extractFilename(overlay);
            await utils.downloadToFile(overlayPath, 'frontend/dist/frontend/assets/private/' + overlay);
        }
        replaceImagePath(overlay);
    }
    if (config_1.default.has('application.easterEggPlanet.name')) {
        replaceThreeJsTitleTag();
    }
};
const replaceImagePath = (overlay) => {
    const textureDeclaration = 'orangeTexture = THREE.ImageUtils.loadTexture("/assets/private/' + overlay + '");';
    (0, replace_1.default)({
        regex: /orangeTexture = .*;/,
        replacement: textureDeclaration,
        paths: ['frontend/dist/frontend/assets/private/threejs-demo.html'],
        recursive: false,
        silent: true
    });
};
const replaceThreeJsTitleTag = () => {
    const threeJsTitleTag = '<title>Welcome to Planet ' + config_1.default.get('application.easterEggPlanet.name') + '</title>';
    (0, replace_1.default)({
        regex: /<title>.*<\/title>/,
        replacement: threeJsTitleTag,
        paths: ['frontend/dist/frontend/assets/private/threejs-demo.html'],
        recursive: false,
        silent: true
    });
};
exports.default = customizeEasterEgg;
//# sourceMappingURL=customizeEasterEgg.js.map