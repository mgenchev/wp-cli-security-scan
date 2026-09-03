<?php
/** Regression test: report finalization must work without WordPress path constants. */
// Intentionally do not define ABSPATH/WP_CONTENT_DIR/WP_PLUGIN_DIR/WPMU_PLUGIN_DIR.
define('WP_CLI', true);
class WP_CLI {
    public static $logs = [];
    public static function add_command($name,$class) {}
    public static function log($m=''){ self::$logs[]=(string)$m; }
    public static function warning($m){ self::$logs[]='Warning: '.$m; }
    public static function success($m){ self::$logs[]='Success: '.$m; }
    public static function error($m){ throw new RuntimeException($m); }
}
require dirname(__DIR__).'/src/SecurityScanCommand.php';
$c = new Security_Scan_Command();
$set = function($name,$value) use ($c){ $p=new ReflectionProperty($c,$name); $p->setAccessible(true); $p->setValue($c,$value); };
$set('interactive', false);
$set('format', 'table');
$set('launch_directory', sys_get_temp_dir());
$set('start_time', microtime(true)-1);
$set('findings', [
 ['section'=>'Plugins','severity'=>'high','confidence'=>90,'description'=>'Test issue','location'=>'plugins/foo/a.php','line'=>1,'rule'=>'test'],
]);
$set('plugin_integrity', [
 'foo'=>['status'=>'modified','source'=>'wordpress.org','checksum_errors'=>[['file'=>'a.php','message'=>'File differs from the official plugin checksum']]],
]);
$set('inactive_plugins', [['slug'=>'inactive','name'=>'Inactive Plugin','file'=>'inactive/main.php']]);
$set('inactive_themes', [['slug'=>'theme','name'=>'Theme']]);
$m=new ReflectionMethod($c,'finalize_report'); $m->setAccessible(true);
try { $m->invoke($c, []); echo "Isolated finalization smoke tests passed.\n"; echo implode("\n", WP_CLI::$logs),"\n"; }
catch(Throwable $e){ echo "ERR: ".$e->getMessage()." @ ".$e->getFile().':'.$e->getLine()."\n"; echo $e->getTraceAsString(),"\n"; exit(1); }
