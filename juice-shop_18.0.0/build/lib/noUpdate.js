"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.makeKeyNonUpdatable = void 0;
// @ts-expect-error FIXME due to non-existing type definitions for sequelize/lib/errors
const errors_1 = require("sequelize/lib/errors");
const makeKeyNonUpdatable = (model, column) => {
    model.addHook('beforeValidate', (instance, options) => {
        if (!options.validate)
            return;
        if (instance.isNewRecord)
            return;
        const changedKeys = [];
        const instanceChanged = Array.from(instance._changed);
        instanceChanged.forEach((value) => changedKeys.push(value));
        if (changedKeys.length === 0)
            return;
        const validationErrors = [];
        changedKeys.forEach((fieldName) => {
            const fieldDefinition = instance.rawAttributes[fieldName];
            if (instance._previousDataValues[fieldName] !== undefined &&
                instance._previousDataValues[fieldName] !== null &&
                (fieldDefinition.fieldName === column)) {
                validationErrors.push(new errors_1.ValidationErrorItem(`\`${fieldName}\` cannot be updated due \`noUpdate\` constraint`, 'noUpdate Violation', fieldName));
            }
        });
        if (validationErrors.length > 0) {
            throw new errors_1.ValidationError(null, validationErrors);
        }
    });
};
exports.makeKeyNonUpdatable = makeKeyNonUpdatable;
//# sourceMappingURL=noUpdate.js.map