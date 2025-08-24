# grunt-replace-json

> Updates attributes of json files

## Getting Started
This plugin requires Grunt `~0.4.5`

If you haven't used [Grunt](http://gruntjs.com/) before, be sure to check out the [Getting Started](http://gruntjs.com/getting-started) guide, as it explains how to create a [Gruntfile](http://gruntjs.com/sample-gruntfile) as well as install and use Grunt plugins. Once you're familiar with that process, you may install this plugin with this command:

```shell
npm install grunt-replace-json --save-dev
```

Once the plugin has been installed, it may be enabled inside your Gruntfile with this line of JavaScript:

```js
grunt.loadNpmTasks('grunt-replace-json');
```

## The "replace_json" task

### Overview
In your project's Gruntfile, add a section named `replace_json` to the data object passed into `grunt.initConfig()`.

```js
grunt.initConfig({
  replace_json: {
    your_target: {
      // Target-specific src and changes go here.
    },
  },
});
```

### Options

#### src

The path of the file where the changes will be applied.

#### changes

A JSON object of the changes to be applied. Each key is the attribute name for a single property or  *attribute0*.*attribute1*.(...).*attributeN*
for nested attributes. If the attribute isn't present in the file, it will be added.

### Usage Example

In this example we change the version of the dotenv dependency and add a new one in our `package.json`.

```js
grunt.initConfig({
  replace_json: {
    dotenv:{
        src: 'dist/package.json',
        changes: {
            'dependencies.dotenv': '^2.0.0',
            'dependencies.grunt': '^0.4.2'
        }
    },
  },
});
```

Initial file:
```json
{
    "dependencies": {
        "dotenv": "^1.0.0",
    }
}

```
Result file:
```json
{
    "dependencies": {
        "dotenv": "^2.0.0",
        "grunt": "^0.4.2"
    }
}
```
