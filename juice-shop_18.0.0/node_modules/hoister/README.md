hoister
=======

Put all function and variable declarations at the top of the scope in an AST 

[![NPM](https://nodei.co/npm/hoister.png?compact=true)](https://nodei.co/npm/hoister/)

## Example

```js
var parse = require('esprima').parse
var generate = require('escodegen').generate
var hoist = require('hoist')

var src = 'a = func(123); var a = "test"; function func(x){return x}'
var ast = parse(src)
hoist(ast)

console.log(generate(ast))
```

Console result:

```js
function func(x) {
  return x;
}
var a;
a = func(123);
var a = 'test';
```