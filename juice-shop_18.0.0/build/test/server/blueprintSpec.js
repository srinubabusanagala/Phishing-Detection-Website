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
const chai_1 = __importDefault(require("chai"));
const config_1 = __importDefault(require("config"));
const node_fs_1 = __importDefault(require("node:fs"));
const node_path_1 = __importDefault(require("node:path"));
const exif_1 = require("exif");
const node_stream_1 = require("node:stream");
const sinon_chai_1 = __importDefault(require("sinon-chai"));
const utils = __importStar(require("../../lib/utils"));
const promises_1 = require("node:stream/promises");
const expect = chai_1.default.expect;
chai_1.default.use(sinon_chai_1.default);
async function parseExifData(path) {
    return await new Promise((resolve, reject) => {
        // eslint-disable-next-line no-new
        new exif_1.ExifImage({ image: path }, (error, exifData) => {
            if (error != null) {
                expect.fail(`Could not read EXIF data from ${path}`);
                reject(error);
            }
            resolve(exifData);
        });
    });
}
describe('blueprint', () => {
    const products = config_1.default.get('products');
    let pathToImage = 'assets/public/images/products/';
    describe('checkExifData', () => {
        it('should contain properties from exifForBlueprintChallenge', async () => {
            for (const product of products) {
                if (product.fileForRetrieveBlueprintChallenge && product.image) {
                    if (utils.isUrl(product.image)) {
                        pathToImage = node_path_1.default.resolve('frontend/dist/frontend', pathToImage, product.image.substring(product.image.lastIndexOf('/') + 1));
                        const response = await fetch(product.image);
                        if (!response.ok || !response.body) {
                            expect.fail(`Could not download image from ${product.image}`);
                            return;
                        }
                        const fileStream = node_fs_1.default.createWriteStream(pathToImage, { flags: 'w' });
                        await (0, promises_1.finished)(node_stream_1.Readable.fromWeb(response.body).pipe(fileStream));
                    }
                    else {
                        pathToImage = node_path_1.default.resolve('frontend/src', pathToImage, product.image);
                    }
                    if (product.exifForBlueprintChallenge?.[0]) { // Prevents failing test for sample or custom themes where null has been explicitly set as value for "exifForBlueprintChallenge". Warning: This makes the "Retrieve Blueprint" challenge probably unsolvable unless hints are placed elsewhere.
                        try {
                            const exifData = await parseExifData(pathToImage);
                            const properties = Object.values(exifData.image);
                            for (const property of product.exifForBlueprintChallenge) {
                                expect(properties).to.include(property);
                            }
                        }
                        catch (error) {
                            expect.fail(`Could not read EXIF data from ${pathToImage}`);
                        }
                    }
                }
            }
        });
    });
});
//# sourceMappingURL=blueprintSpec.js.map