'use strict';
var set = require('lodash.set');

function replaceJson(grunt) {
    grunt.registerMultiTask('replace_json', 'Update attributes of json file.', function() {
        var srcFile = this.data.src;
        var changes = this.data.changes;

        if (!grunt.file.exists(srcFile)) {
            grunt.log.error('file: ' + srcFile + ' not found');
            return false;
        }

        var file = grunt.file.readJSON(srcFile);

        Object.keys(changes).forEach(function(key) {
            set(file, key, changes[key]);
        });

        grunt.file.write(srcFile, JSON.stringify(file, null, 2));

        return true;
    });
}

module.exports = replaceJson;
