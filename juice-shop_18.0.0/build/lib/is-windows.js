"use strict";
// from https://github.com/jonschlinkert/is-windows MIT Licensed
// inlined to avoid import problems in cypress
Object.defineProperty(exports, "__esModule", { value: true });
function isWindows() {
    return process && (process.platform === 'win32' || /^(msys|cygwin)$/.test(process.env.OSTYPE ?? ''));
}
exports.default = isWindows;
//# sourceMappingURL=is-windows.js.map