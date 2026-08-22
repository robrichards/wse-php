--TEST--
decryptSoapDoc removes dangling DataReferences and EncryptedKey after decrypt
--FILE--
<?php
require dirname(__FILE__) . '/../wse-php.php';
use RobRichards\WsePhp\WSSESoap;
use RobRichards\XMLSecLibs\XMLSecurityKey;

$priv = dirname(__FILE__) . '/fixtures/privkey.pem';
$cert = dirname(__FILE__) . '/fixtures/mycert.pem';

$doc = new DOMDocument();
$doc->loadXML('<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Header/><soap:Body><ping>1</ping></soap:Body></soap:Envelope>');
$wsse = new WSSESoap($doc);

$session = new XMLSecurityKey(XMLSecurityKey::AES256_CBC);
$session->generateSessionKey();
$siteKey = new XMLSecurityKey(XMLSecurityKey::RSA_OAEP_MGF1P, array('type' => 'public'));
$siteKey->loadKey($cert, true, true);
$wsse->encryptSoapDoc($siteKey, $session, null, false);

$doc2 = new DOMDocument();
$doc2->loadXML($wsse->saveXML());
$wsse2 = new WSSESoap($doc2);
$wsse2->decryptSoapDoc($doc2, array(
    'keys' => array('private' => array('key' => $priv, 'isFile' => true, 'isCert' => false)),
));

$xml = $doc2->saveXML();
$xpath = new DOMXPath($doc2);
$xpath->registerNamespace('soapenc', 'http://www.w3.org/2001/04/xmlenc#');

echo (strpos($xml, '<ping>1</ping>') !== false ? 'BODY_OK' : 'BODY_FAIL')."\n";
echo ($xpath->query('//soapenc:EncryptedData')->length === 0 ? 'NO_ENC_DATA' : 'HAS_ENC_DATA')."\n";
echo ($xpath->query('//soapenc:DataReference')->length === 0 ? 'NO_DATA_REF' : 'HAS_DATA_REF')."\n";
echo ($xpath->query('//soapenc:EncryptedKey')->length === 0 ? 'NO_ENC_KEY' : 'HAS_ENC_KEY')."\n";
?>
--EXPECTF--
BODY_OK
NO_ENC_DATA
NO_DATA_REF
NO_ENC_KEY
