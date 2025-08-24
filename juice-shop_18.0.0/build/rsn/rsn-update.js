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
    console.log(('---------------------------------------'));
    (0, rsnUtil_1.writeToFile)(data);
    console.log(`${safe_1.default.bold('All file diffs have been locked!')} Commit changed cache.json to git.`);
})
    .catch(err => {
    console.log(err);
    process.exitCode = 1;
});
//# sourceMappingURL=rsn-update.js.map