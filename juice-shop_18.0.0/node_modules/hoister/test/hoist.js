var parse = require('esprima').parse
var hoist = require('../')
var test = require('tape')

test('hoist', function(t){
  var src = 'a = func(123); var a = "test"; function func(x){return x}'
  var expected = 'function func(x){return x} var a; a = func(123); var a = "test"'

  var ast = parse(src)
  hoist(ast)

  t.deepEqual(ast, parse(expected))
  t.end()

})

