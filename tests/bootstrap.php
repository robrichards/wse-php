<?php
/**
 * Test bootstrap for wse-php.
 * Loads the sibling xmlseclibs checkout and this package's src/.
 */
$xmlseclibs = dirname(__FILE__) . '/../../xmlseclibs/xmlseclibs.php';
if (!file_exists($xmlseclibs)) {
    fwrite(STDERR, "Sibling xmlseclibs not found at $xmlseclibs\n");
    exit(1);
}
require $xmlseclibs;

spl_autoload_register(function ($class) {
    $prefix = 'RobRichards\\WsePhp\\';
    if (strncmp($prefix, $class, strlen($prefix)) !== 0) {
        return;
    }
    $relative = substr($class, strlen($prefix));
    $file = dirname(__FILE__) . '/../src/' . str_replace('\\', '/', $relative) . '.php';
    if (file_exists($file)) {
        require $file;
    }
});
