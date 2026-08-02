--TEST--
WSASoap addMessageID returns ID on first call; 2005 anonymous URI
--FILE--
<?php
require dirname(__FILE__) . '/bootstrap.php';
use RobRichards\WsePhp\WSASoap;

$doc = new DOMDocument();
$doc->loadXML('<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body/></soap:Envelope>');
$wsa = new WSASoap($doc, WSASoap::WSANS_2005);
$id = $wsa->addMessageID('uuid:test-1');
echo ($id === 'uuid:test-1' ? 'ID_OK' : 'ID_FAIL')."\n";
echo ($wsa->addMessageID() === 'uuid:test-1' ? 'ID2_OK' : 'ID2_FAIL')."\n";
$wsa->addReplyTo();
$xml = $doc->saveXML();
echo (strpos($xml, 'http://www.w3.org/2005/08/addressing/anonymous') !== false ? 'ANON_OK' : 'ANON_FAIL')."\n";
?>
--EXPECTF--
ID_OK
ID2_OK
ANON_OK
