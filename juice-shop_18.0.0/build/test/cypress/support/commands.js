"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
Cypress.Commands.add('expectChallengeSolved', (context) => {
    cy.request({
        method: 'GET',
        url: '/api/Challenges/?name=' + context.challenge,
        timeout: 60000
    }).then((response) => {
        let challenge = response.body.data[0];
        if (!challenge.solved) {
            cy.wait(2000);
            cy.request({
                method: 'GET',
                url: '/api/Challenges/?name=' + context.challenge,
                timeout: 60000
            }).then((secondResponse) => {
                challenge = secondResponse.body.data[0];
                // eslint-disable-next-line @typescript-eslint/no-unused-expressions
                expect(challenge.solved).to.be.true;
            });
        }
        else {
            // eslint-disable-next-line @typescript-eslint/no-unused-expressions
            expect(challenge.solved).to.be.true;
        }
    });
});
Cypress.Commands.add('login', (context) => {
    cy.visit('/#/login');
    if (context.email.match(/\S+@\S+\.\S+/) != null) {
        cy.get('#email').type(context.email);
    }
    else {
        cy.task('GetFromConfig', 'application.domain').then((appDomain) => {
            const email = context.email.concat('@', appDomain);
            cy.get('#email').type(email);
        });
    }
    cy.get('#password').type(context.password);
    cy.get('#loginButton').click();
    cy.wait(500);
});
function walkRecursivelyInArray(arr, cb, index = 0) {
    if (arr.length === 0)
        return;
    const ret = cb(index, arr.shift());
    // eslint-disable-next-line @typescript-eslint/prefer-optional-chain
    ((ret && ret.chainerId) ? ret : cy.wrap(ret))
        .then((ret) => {
        if (!ret)
            return;
        walkRecursivelyInArray(arr, cb, index + 1);
    });
}
Cypress.Commands.add('eachSeries', { prevSubject: 'optional' }, (arrayGenerated, checkFnToBeRunOnEach) => {
    walkRecursivelyInArray(arrayGenerated, checkFnToBeRunOnEach);
});
//# sourceMappingURL=commands.js.map