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
Object.defineProperty(exports, "__esModule", { value: true });
exports.nftUnlocked = exports.checkKeys = void 0;
const ethers_1 = require("ethers");
const challengeUtils = __importStar(require("../lib/challengeUtils"));
const utils = __importStar(require("../lib/utils"));
const datacache_1 = require("../data/datacache");
function checkKeys() {
    return (req, res) => {
        try {
            const mnemonic = 'purpose betray marriage blame crunch monitor spin slide donate sport lift clutch';
            const mnemonicWallet = ethers_1.HDNodeWallet.fromPhrase(mnemonic);
            const privateKey = mnemonicWallet.privateKey;
            const publicKey = mnemonicWallet.publicKey;
            const address = mnemonicWallet.address;
            challengeUtils.solveIf(datacache_1.challenges.nftUnlockChallenge, () => {
                return req.body.privateKey === privateKey;
            });
            if (req.body.privateKey === privateKey) {
                res.status(200).json({ success: true, message: 'Challenge successfully solved', status: datacache_1.challenges.nftUnlockChallenge });
            }
            else {
                if (req.body.privateKey === address) {
                    res.status(401).json({ success: false, message: 'Looks like you entered the public address of my ethereum wallet!', status: datacache_1.challenges.nftUnlockChallenge });
                }
                else if (req.body.privateKey === publicKey) {
                    res.status(401).json({ success: false, message: 'Looks like you entered the public key of my ethereum wallet!', status: datacache_1.challenges.nftUnlockChallenge });
                }
                else {
                    res.status(401).json({ success: false, message: 'Looks like you entered a non-Ethereum private key to access me.', status: datacache_1.challenges.nftUnlockChallenge });
                }
            }
        }
        catch (error) {
            res.status(500).json(utils.getErrorMessage(error));
        }
    };
}
exports.checkKeys = checkKeys;
function nftUnlocked() {
    return (req, res) => {
        try {
            res.status(200).json({ status: datacache_1.challenges.nftUnlockChallenge.solved });
        }
        catch (error) {
            res.status(500).json(utils.getErrorMessage(error));
        }
    };
}
exports.nftUnlocked = nftUnlocked;
//# sourceMappingURL=checkKeys.js.map