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
exports.checkCorrectFix = exports.serveCodeFixes = exports.readFixes = void 0;
const node_fs_1 = __importDefault(require("node:fs"));
const js_yaml_1 = __importDefault(require("js-yaml"));
const accuracy = __importStar(require("../lib/accuracy"));
const challengeUtils = __importStar(require("../lib/challengeUtils"));
const FixesDir = 'data/static/codefixes';
const CodeFixes = {};
const readFixes = (key) => {
    if (CodeFixes[key]) {
        return CodeFixes[key];
    }
    const files = node_fs_1.default.readdirSync(FixesDir);
    const fixes = [];
    let correct = -1;
    for (const file of files) {
        if (file.startsWith(`${key}_`)) {
            const fix = node_fs_1.default.readFileSync(`${FixesDir}/${file}`).toString();
            const metadata = file.split('_');
            const number = metadata[1];
            fixes.push(fix);
            if (metadata.length === 3) {
                correct = parseInt(number, 10);
                correct--;
            }
        }
    }
    CodeFixes[key] = {
        fixes,
        correct
    };
    return CodeFixes[key];
};
exports.readFixes = readFixes;
const serveCodeFixes = () => (req, res, next) => {
    const key = req.params.key;
    const fixData = (0, exports.readFixes)(key);
    if (fixData.fixes.length === 0) {
        res.status(404).json({
            error: 'No fixes found for the snippet!'
        });
        return;
    }
    res.status(200).json({
        fixes: fixData.fixes
    });
};
exports.serveCodeFixes = serveCodeFixes;
const checkCorrectFix = () => async (req, res, next) => {
    const key = req.body.key;
    const selectedFix = req.body.selectedFix;
    const fixData = (0, exports.readFixes)(key);
    if (fixData.fixes.length === 0) {
        res.status(404).json({
            error: 'No fixes found for the snippet!'
        });
    }
    else {
        let explanation;
        if (node_fs_1.default.existsSync('./data/static/codefixes/' + key + '.info.yml')) {
            const codingChallengeInfos = js_yaml_1.default.load(node_fs_1.default.readFileSync('./data/static/codefixes/' + key + '.info.yml', 'utf8'));
            const selectedFixInfo = codingChallengeInfos?.fixes.find(({ id }) => id === selectedFix + 1);
            if (selectedFixInfo?.explanation)
                explanation = res.__(selectedFixInfo.explanation);
        }
        if (selectedFix === fixData.correct) {
            await challengeUtils.solveFixIt(key);
            res.status(200).json({
                verdict: true,
                explanation
            });
        }
        else {
            accuracy.storeFixItVerdict(key, false);
            res.status(200).json({
                verdict: false,
                explanation
            });
        }
    }
};
exports.checkCorrectFix = checkCorrectFix;
//# sourceMappingURL=vulnCodeFixes.js.map