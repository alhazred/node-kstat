var kstat = require('kstat');
var sys = require('sys');
var reader = new kstat.Reader({ 'class': 'misc', module: 'cpu_stat', name: 'cpu_stat1' } );
sys.puts(sys.inspect(reader.read()));
