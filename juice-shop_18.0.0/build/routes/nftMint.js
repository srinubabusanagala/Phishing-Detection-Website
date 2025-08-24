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
exports.walletNFTVerify = exports.nftMintListener = void 0;
const ethers_1 = require("ethers");
const challengeUtils = __importStar(require("../lib/challengeUtils"));
const contractABIs_1 = require("../data/static/contractABIs");
const datacache_1 = require("../data/datacache");
const utils = __importStar(require("../lib/utils"));
const nftAddress = '0x41427790c94E7a592B17ad694eD9c06A02bb9C39';
const addressesMinted = new Set();
let isEventListenerCreated = false;
function nftMintListener() {
    return async (req, res) => {
        try {
            const provider = new ethers_1.WebSocketProvider('wss://eth-sepolia.g.alchemy.com/v2/FZDapFZSs1l6yhHW4VnQqsi18qSd-3GJ');
            const contract = new ethers_1.Contract(nftAddress, contractABIs_1.nftABI, provider);
            if (!isEventListenerCreated) {
                void contract.on('NFTMinted', (minter) => {
                    if (!addressesMinted.has(minter)) {
                        addressesMinted.add(minter);
                    }
                });
                isEventListenerCreated = true;
            }
            res.status(200).json({ success: true, message: 'Event Listener Created' });
        }
        catch (error) {
            res.status(500).json(utils.getErrorMessage(error));
        }
    };
}
exports.nftMintListener = nftMintListener;
function walletNFTVerify() {
    return (req, res) => {
        try {
            const metamaskAddress = req.body.walletAddress;
            if (addressesMinted.has(metamaskAddress)) {
                addressesMinted.delete(metamaskAddress);
                challengeUtils.solveIf(datacache_1.challenges.nftMintChallenge, () => true);
                res.status(200).json({ success: true, message: 'Challenge successfully solved', status: datacache_1.challenges.nftMintChallenge });
            }
            else {
                res.status(200).json({ success: false, message: 'Wallet did not mint the NFT', status: datacache_1.challenges.nftMintChallenge });
            }
        }
        catch (error) {
            res.status(500).json(utils.getErrorMessage(error));
        }
    };
}
exports.walletNFTVerify = walletNFTVerify;
//# sourceMappingURL=nftMint.js.map