--TEST--
encryptSoapDoc does not fatal when KeyInfo uses BinarySecurityToken fallback
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

$signKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA1, array('type' => 'private'));
$signKey->loadKey($priv, true);
$wsse->signSoapDoc($signKey, array('insertBefore' => false));
$token = $wsse->addBinaryToken(file_get_contents($cert));
$wsse->attachTokentoSig($token);

$session = new XMLSecurityKey(XMLSecurityKey::AES256_CBC);
$session->generateSessionKey();
$siteKey = new XMLSecurityKey(XMLSecurityKey::RSA_OAEP_MGF1P, array('type' => 'public'));
$siteKey->loadKey($cert, true, true);

/* No KeyInfo options: previously fatal when $siteKey was treated as a DOM token. */
$wsse->encryptSoapDoc($siteKey, $session, null, false);

$xml = $wsse->saveXML();
$hasEncKey = strpos($xml, 'EncryptedKey') !== false;

$doc2 = new DOMDocument();
$doc2->loadXML($xml);
$xpath = new DOMXPath($doc2);
$sec = $xpath->query('//*[local-name()="Security"]')->item(0);
$names = array();
foreach ($sec->childNodes as $child) {
    if ($child->nodeType === XML_ELEMENT_NODE) {
        $names[] = $child->localName;
    }
}
$encPos = array_search('EncryptedKey', $names, true);
$sigPos = array_search('Signature', $names, true);
$encBeforeSig = ($encPos !== false && $sigPos !== false && $encPos < $sigPos);
echo ($hasEncKey ? 'ENC_OK' : 'ENC_FAIL')."\n";
echo ($encBeforeSig ? 'ORDER_OK' : 'ORDER_FAIL:'.implode(',', $names))."\n";
echo (strpos($xml, 'BinarySecurityToken') !== false ? 'BST_OK' : 'BST_FAIL')."\n";
?>
--EXPECTF--
ENC_OK
ORDER_OK
BST_OK
