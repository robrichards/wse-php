--TEST--
signSoapDoc X509SubjectKeyIdentifier works when Signature is sole Security child
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

$signKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA1, array('type' => 'private'));
$signKey->loadKey($priv, true);
$signKey->loadKey(file_get_contents($cert), false, true);
/* Re-load private key after cert so signing still works; attach cert separately via loadKey isCert. */
$signKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA1, array('type' => 'private'));
$signKey->loadKey($priv, true);
/* Put cert PEM on key via isCert path on a public load is wrong for private key.
   Use openssl to attach x509 by loading cert into a temp public key object is not available.
   Instead: load private key then manually set certificate through loadKey with isCert on a clone.
   XMLSecurityKey keeps x509Certificate only when isCert=true, which clears private key use.
   For SKI we need getX509Certificate() set. Reflect or use loadKey isCert after copying.
*/
$ref = new ReflectionClass($signKey);
/* Reload using PEM that is private key, then set x509 via reflection of private prop if needed. */
$pemCert = file_get_contents($cert);
$prop = $ref->getProperty('x509Certificate');
$prop->setAccessible(true);
$prop->setValue($signKey, $pemCert);

$wsse->signSoapDoc($signKey, array(
    'insertBefore' => true,
    'KeyInfo' => array('X509SubjectKeyIdentifier' => true),
));

$xml = $wsse->saveXML();
echo (strpos($xml, 'X509SubjectKeyIdentifier') !== false ? 'SKI_OK' : 'SKI_FAIL')."\n";
echo (strpos($xml, 'KeyIdentifier') !== false ? 'KID_OK' : 'KID_FAIL')."\n";
?>
--EXPECTF--
SKI_OK
KID_OK
