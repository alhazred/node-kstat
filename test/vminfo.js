var kstat = require('kstat');
var sys = require('sys');
var reader = new kstat.Reader({ 'class': 'vm', module: 'unix', name: 'vminfo' } );
sys.puts(sys.inspect(reader.read()));
