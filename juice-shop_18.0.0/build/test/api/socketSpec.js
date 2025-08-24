"use strict";
/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const socket_io_client_1 = __importDefault(require("socket.io-client"));
describe('WebSocket', () => {
    let socket;
    beforeEach(done => {
        socket = (0, socket_io_client_1.default)('http://localhost:3000', {
            reconnectionDelay: 0,
            forceNew: true
        });
        socket.on('connect', () => {
            done();
        });
    });
    afterEach(done => {
        if (socket.connected) {
            socket.disconnect();
        }
        done();
    });
    it('server handles confirmation messages for emitted challenge resolutions', done => {
        socket.emit('notification received', 'Find the carefully hidden \'Score Board\' page.');
        socket.emit('notification received', 'Provoke an error that is not very gracefully handled.');
        socket.emit('notification received', 'Log in with the administrator\'s user account.');
        socket.emit('notification received', 'Retrieve a list of all user credentials via SQL Injection');
        socket.emit('notification received', 'Post some feedback in another user\'s name.');
        socket.emit('notification received', 'Wherever you go, there you are.');
        socket.emit('notification received', 'Place an order that makes you rich.');
        socket.emit('notification received', 'Access a confidential document.');
        socket.emit('notification received', 'Access a salesman\'s forgotten backup file.');
        socket.emit('notification received', 'Change Bender\'s password into slurmCl4ssic.');
        socket.emit('notification received', 'Apply some advanced cryptanalysis to find the real easter egg.');
        done();
    });
    it('server handles confirmation message for a non-existent challenge', done => {
        socket.emit('notification received', 'Emit a confirmation for a challenge that was never emitted!');
        done();
    });
    it('server handles empty confirmation message', done => {
        socket.emit('notification received', undefined);
        done();
    });
});
//# sourceMappingURL=socketSpec.js.map