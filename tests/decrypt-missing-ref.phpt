--TEST--
decryptSoapDoc throws on missing EncryptedData reference instead of fatal
--FILE--
<?php
require dirname(__FILE__) . '/bootstrap.php';
use RobRichards\WsePhp\WSSESoap;
use RobRichards\XMLSecLibs\XMLSecurityKey;

$priv = dirname(__FILE__) . '/../../xmlseclibs/tests/privkey.pem';
$cert = dirname(__FILE__) . '/../../xmlseclibs/tests/mycert.pem';

$doc = new DOMDocument();
$doc->loadXML('<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Header/><soap:Body><ping>1</ping></soap:Body></soap:Envelope>');
$wsse = new WSSESoap($doc);

$session = new XMLSecurityKey(XMLSecurityKey::AES256_CBC);
$session->generateSessionKey();
$siteKey = new XMLSecurityKey(XMLSecurityKey::RSA_OAEP_MGF1P, array('type' => 'public'));
$siteKey->loadKey($cert, true, true);
$wsse->encryptSoapDoc($siteKey, $session, null, false);

$xml = $wsse->saveXML();
/* Point DataReference at a missing Id so decrypt finds EncryptedKey but not EncryptedData. */
$xml = preg_replace('/DataReference URI="#[^"]+"/', 'DataReference URI="#does-not-exist"', $xml, 1);

$doc2 = new DOMDocument();
$doc2->loadXML($xml);
$wsse2 = new WSSESoap($doc2);
try {
    $wsse2->decryptSoapDoc($doc2, array(
        'keys' => array('private' => array('key' => $priv, 'isFile' => true, 'isCert' => false)),
    ));
    echo "UNEXPECTED_SUCCESS\n";
} catch (Exception $e) {
    echo (strpos($e->getMessage(), 'Unable to locate EncryptedData') !== false ? 'THREW_OK' : 'THREW_OTHER: '.$e->getMessage())."\n";
}
?>
--EXPECTF--
THREW_OK
