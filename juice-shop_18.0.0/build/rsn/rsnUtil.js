"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.checkData = exports.seePatch = exports.readFiles = exports.getDataFromFile = exports.writeToFile = exports.checkDiffs = void 0;
const node_fs_1 = __importDefault(require("node:fs"));
const safe_1 = __importDefault(require("colors/safe"));
const diff_1 = require("diff");
const vulnCodeSnippet_1 = require("../routes/vulnCodeSnippet");
const fixesPath = 'data/static/codefixes';
const cacheFile = 'rsn/cache.json';
function readFiles() {
    const files = node_fs_1.default.readdirSync(fixesPath);
    const keys = files.filter((file) => !file.endsWith('.info.yml') && !file.endsWith('.editorconfig'));
    return keys;
}
exports.readFiles = readFiles;
function writeToFile(json) {
    node_fs_1.default.writeFileSync(cacheFile, JSON.stringify(json, null, '\t'));
}
exports.writeToFile = writeToFile;
function getDataFromFile() {
    const data = node_fs_1.default.readFileSync(cacheFile).toString();
    return JSON.parse(data);
}
exports.getDataFromFile = getDataFromFile;
function filterString(text) {
    text = text.replace(/\r/g, '');
    return text;
}
const checkDiffs = async (keys) => {
    const data = keys.reduce((prev, curr) => {
        return {
            ...prev,
            [curr]: {
                added: [],
                removed: []
            }
        };
    }, {});
    for (const val of keys) {
        await (0, vulnCodeSnippet_1.retrieveCodeSnippet)(val.split('_')[0])
            .then(snippet => {
            if (snippet == null)
                return;
            process.stdout.write(val + ': ');
            const fileData = node_fs_1.default.readFileSync(fixesPath + '/' + val).toString();
            const diff = (0, diff_1.diffLines)(filterString(fileData), filterString(snippet.snippet));
            let line = 0;
            for (const part of diff) {
                if (!part.count)
                    continue;
                if (part.removed)
                    continue;
                const prev = line;
                line += part.count;
                if (!(part.added))
                    continue;
                for (let i = 0; i < part.count; i++) {
                    if (!snippet.vulnLines.includes(prev + i + 1) && !snippet.neutralLines.includes(prev + i + 1)) {
                        process.stdout.write(safe_1.default.red(safe_1.default.inverse(prev + i + 1 + '')));
                        process.stdout.write(' ');
                        data[val].added.push(prev + i + 1);
                    }
                    else if (snippet.vulnLines.includes(prev + i + 1)) {
                        process.stdout.write(safe_1.default.red(safe_1.default.bold(prev + i + 1 + ' ')));
                    }
                    else if (snippet.neutralLines.includes(prev + i + 1)) {
                        process.stdout.write(safe_1.default.red(prev + i + 1 + ' '));
                    }
                }
            }
            line = 0;
            let norm = 0;
            for (const part of diff) {
                if (!part.count)
                    continue;
                if (part.added) {
                    norm--;
                    continue;
                }
                const prev = line;
                line += part.count;
                if (!(part.removed))
                    continue;
                let temp = norm;
                for (let i = 0; i < part.count; i++) {
                    if (!snippet.vulnLines.includes(prev + i + 1 - norm) && !snippet.neutralLines.includes(prev + i + 1 - norm)) {
                        process.stdout.write(safe_1.default.green(safe_1.default.inverse((prev + i + 1 - norm + ''))));
                        process.stdout.write(' ');
                        data[val].removed.push(prev + i + 1 - norm);
                    }
                    else if (snippet.vulnLines.includes(prev + i + 1 - norm)) {
                        process.stdout.write(safe_1.default.green(safe_1.default.bold(prev + i + 1 - norm + ' ')));
                    }
                    else if (snippet.neutralLines.includes(prev + i + 1 - norm)) {
                        process.stdout.write(safe_1.default.green(prev + i + 1 - norm + ' '));
                    }
                    temp++;
                }
                norm = temp;
            }
            process.stdout.write('\n');
        })
            .catch(err => {
            console.log(err);
        });
    }
    return data;
};
exports.checkDiffs = checkDiffs;
async function seePatch(file) {
    const fileData = node_fs_1.default.readFileSync(fixesPath + '/' + file).toString();
    const snippet = await (0, vulnCodeSnippet_1.retrieveCodeSnippet)(file.split('_')[0]);
    if (snippet == null)
        return;
    const patch = (0, diff_1.structuredPatch)(file, file, filterString(snippet.snippet), filterString(fileData));
    console.log(safe_1.default.bold(file + '\n'));
    for (const hunk of patch.hunks) {
        for (const line of hunk.lines) {
            if (line[0] === '-') {
                console.log(safe_1.default.red(line));
            }
            else if (line[0] === '+') {
                console.log(safe_1.default.green(line));
            }
            else {
                console.log(line);
            }
        }
    }
    console.log('---------------------------------------');
}
exports.seePatch = seePatch;
function checkData(data, fileData) {
    const filesWithDiff = [];
    for (const key in data) {
        const fileDataValueAdded = fileData[key].added.sort((a, b) => a - b);
        const dataValueAdded = data[key].added.sort((a, b) => a - b);
        const fileDataValueRemoved = fileData[key].added.sort((a, b) => a - b);
        const dataValueAddedRemoved = data[key].added.sort((a, b) => a - b);
        if (fileDataValueAdded.length === dataValueAdded.length && fileDataValueRemoved.length === dataValueAddedRemoved.length) {
            if (!dataValueAdded.every((val, ind) => fileDataValueAdded[ind] === val)) {
                console.log(safe_1.default.red(key));
                filesWithDiff.push(key);
            }
            if (!dataValueAddedRemoved.every((val, ind) => fileDataValueRemoved[ind] === val)) {
                console.log(safe_1.default.red(key));
                filesWithDiff.push(key);
            }
        }
        else {
            console.log(safe_1.default.red(key));
            filesWithDiff.push(key);
        }
    }
    return filesWithDiff;
}
exports.checkData = checkData;
//# sourceMappingURL=rsnUtil.js.map