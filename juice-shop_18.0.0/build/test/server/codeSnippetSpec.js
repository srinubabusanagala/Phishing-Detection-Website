"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const chai_1 = __importDefault(require("chai"));
const sinon_chai_1 = __importDefault(require("sinon-chai"));
const vulnCodeSnippet_1 = require("../../routes/vulnCodeSnippet");
const expect = chai_1.default.expect;
chai_1.default.use(sinon_chai_1.default);
describe('vulnCodeSnippet', () => {
    it('should assert single correctly selected vuln line as correct', () => {
        expect((0, vulnCodeSnippet_1.getVerdict)([1], [], [1])).to.equal(true);
    });
    it('should assert multiple correctly selected vuln lines as correct in any order', () => {
        expect((0, vulnCodeSnippet_1.getVerdict)([1, 2], [], [1, 2])).to.equal(true);
        expect((0, vulnCodeSnippet_1.getVerdict)([1, 2], [], [2, 1])).to.equal(true);
        expect((0, vulnCodeSnippet_1.getVerdict)([1, 2, 3], [], [3, 1, 2])).to.equal(true);
    });
    it('should ignore selected neutral lines during correct assertion', () => {
        expect((0, vulnCodeSnippet_1.getVerdict)([1, 2], [3, 4], [1, 2, 3])).to.equal(true);
        expect((0, vulnCodeSnippet_1.getVerdict)([1, 2], [3, 4], [1, 2, 4])).to.equal(true);
        expect((0, vulnCodeSnippet_1.getVerdict)([1, 2], [3, 4], [1, 2, 3, 4])).to.equal(true);
    });
    it('should assert missing vuln lines as wrong', () => {
        expect((0, vulnCodeSnippet_1.getVerdict)([1, 2], [], [1])).to.equal(false);
        expect((0, vulnCodeSnippet_1.getVerdict)([1, 2], [], [2])).to.equal(false);
        expect((0, vulnCodeSnippet_1.getVerdict)([1, 2], [3], [2, 3])).to.equal(false);
        expect((0, vulnCodeSnippet_1.getVerdict)([1, 2], [3], [1, 3])).to.equal(false);
        expect((0, vulnCodeSnippet_1.getVerdict)([1, 2], [3, 4], [3, 4])).to.equal(false);
    });
    it('should assert additionally selected lines as wrong', () => {
        expect((0, vulnCodeSnippet_1.getVerdict)([1, 2], [], [1, 2, 3])).to.equal(false);
        expect((0, vulnCodeSnippet_1.getVerdict)([1, 2], [3], [1, 2, 3, 4])).to.equal(false);
    });
    it('should assert lack of selected lines as wrong', () => {
        expect((0, vulnCodeSnippet_1.getVerdict)([1, 2], [], [])).to.equal(false);
    });
    it('should assert empty edge case as correct', () => {
        expect((0, vulnCodeSnippet_1.getVerdict)([], [], [])).to.equal(true);
    });
});
//# sourceMappingURL=codeSnippetSpec.js.map