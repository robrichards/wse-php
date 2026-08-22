--TEST--
WSSESoapServer exposes signing key after successful process()
--FILE--
<?php
require dirname(__FILE__) . '/../wse-php.php';
use RobRichards\WsePhp\WSSESoap;
use RobRichards\WsePhp\WSSESoapServer;
use RobRichards\XMLSecLibs\XMLSecurityKey;

$priv = dirname(__FILE__) . '/fixtures/privkey.pem';
$cert = dirname(__FILE__) . '/fixtures/mycert.pem';

$expectedKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA1, array('type' => 'public'));
$expectedKey->loadKey($cert, true, true);
$expectedThumbprint = $expectedKey->getX509Thumbprint();

$doc = new DOMDocument();
$doc->loadXML('<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Header/><soap:Body><ping>1</ping></soap:Body></soap:Envelope>');
$wsse = new WSSESoap($doc);

$signKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA1, array('type' => 'private'));
$signKey->loadKey($priv, true);
$wsse->signSoapDoc($signKey, array('insertBefore' => true));
$token = $wsse->addBinaryToken(file_get_contents($cert));
$wsse->attachTokentoSig($token);

$signed = new DOMDocument();
$signed->loadXML($wsse->saveXML());
$server = new WSSESoapServer($signed);

echo ($server->getSigningKey() === null ? 'NULL_BEFORE_OK' : 'NULL_BEFORE_FAIL')."\n";

if (!$server->process()) {
    echo "PROCESS_FAIL\n";
    exit(1);
}

$signingKey = $server->getSigningKey();
echo ($signingKey instanceof XMLSecurityKey ? 'KEY_OK' : 'KEY_FAIL')."\n";
echo ($signingKey && $signingKey->getX509Thumbprint() === $expectedThumbprint ? 'THUMBPRINT_OK' : 'THUMBPRINT_FAIL')."\n";
?>
--EXPECTF--
NULL_BEFORE_OK
KEY_OK
THUMBPRINT_OK
