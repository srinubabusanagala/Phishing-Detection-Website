"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const rsnUtil_1 = require("./rsnUtil");
const safe_1 = __importDefault(require("colors/safe"));
const keys = (0, rsnUtil_1.readFiles)();
(0, rsnUtil_1.checkDiffs)(keys)
    .then(data => {
    console.log('---------------------------------------');
    const fileData = (0, rsnUtil_1.getDataFromFile)();
    const filesWithDiff = (0, rsnUtil_1.checkData)(data, fileData);
    if (filesWithDiff.length === 0) {
        console.log(`${safe_1.default.green(safe_1.default.bold('No new file diffs recognized since last lock!'))} No action required.`);
    }
    else {
        console.log(`${safe_1.default.red(safe_1.default.bold('New file diffs recognized since last lock!'))} Double-check and amend listed files and lock new state with ${safe_1.default.bold('npm run rsn:update')}`);
        console.log('---------------------------------------');
        process.exitCode = 1;
    }
})
    .catch(err => {
    console.log(err);
    process.exitCode = 1;
});
//# sourceMappingURL=rsn.js.map