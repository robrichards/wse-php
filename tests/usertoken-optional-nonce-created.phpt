--TEST--
WSSESoap addUserToken optional Nonce and Created
--FILE--
<?php
require dirname(__FILE__) . '/../wse-php.php';
use RobRichards\WsePhp\WSSESoap;

$doc = new DOMDocument();
$doc->loadXML('<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body/></soap:Envelope>');
$wsse = new WSSESoap($doc);
$wsse->addUserToken('user', 'pass');
$xml = $doc->saveXML();
echo (strpos($xml, ':Nonce') !== false ? 'DEFAULT_NONCE_OK' : 'DEFAULT_NONCE_FAIL')."\n";
echo (strpos($xml, ':Created') !== false ? 'DEFAULT_CREATED_OK' : 'DEFAULT_CREATED_FAIL')."\n";

$doc = new DOMDocument();
$doc->loadXML('<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body/></soap:Envelope>');
$wsse = new WSSESoap($doc);
$wsse->addUserToken('user', 'pass', false, false, false);
$xml = $doc->saveXML();
echo (strpos($xml, ':Nonce') === false ? 'OMIT_NONCE_OK' : 'OMIT_NONCE_FAIL')."\n";
echo (strpos($xml, ':Created') === false ? 'OMIT_CREATED_OK' : 'OMIT_CREATED_FAIL')."\n";
echo (strpos($xml, ':Password') !== false ? 'OMIT_PASSWORD_OK' : 'OMIT_PASSWORD_FAIL')."\n";

try {
    $doc = new DOMDocument();
    $doc->loadXML('<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body/></soap:Envelope>');
    $wsse = new WSSESoap($doc);
    $wsse->addUserToken('user', 'pass', true, false, true);
    echo "DIGEST_GUARD_FAIL\n";
} catch (Exception $e) {
    echo "DIGEST_GUARD_OK\n";
}
?>
--EXPECTF--
DEFAULT_NONCE_OK
DEFAULT_CREATED_OK
OMIT_NONCE_OK
OMIT_CREATED_OK
OMIT_PASSWORD_OK
DIGEST_GUARD_OK
