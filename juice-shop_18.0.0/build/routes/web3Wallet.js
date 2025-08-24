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
exports.contractExploitListener = void 0;
const ethers_1 = require("ethers");
const utils = __importStar(require("../lib/utils"));
const datacache_1 = require("../data/datacache");
const challengeUtils = __importStar(require("../lib/challengeUtils"));
const contractABIs_1 = require("../data/static/contractABIs");
const web3WalletAddress = '0x413744D59d31AFDC2889aeE602636177805Bd7b0';
const walletsConnected = new Set();
let isEventListenerCreated = false;
function contractExploitListener() {
    return async (req, res) => {
        const metamaskAddress = req.body.walletAddress;
        walletsConnected.add(metamaskAddress);
        try {
            const provider = new ethers_1.WebSocketProvider('wss://eth-sepolia.g.alchemy.com/v2/FZDapFZSs1l6yhHW4VnQqsi18qSd-3GJ');
            const contract = new ethers_1.Contract(web3WalletAddress, contractABIs_1.web3WalletABI, provider);
            if (!isEventListenerCreated) {
                void contract.on('ContractExploited', (exploiter) => {
                    if (walletsConnected.has(exploiter)) {
                        walletsConnected.delete(exploiter);
                        challengeUtils.solveIf(datacache_1.challenges.web3WalletChallenge, () => true);
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
exports.contractExploitListener = contractExploitListener;
//# sourceMappingURL=web3Wallet.js.map