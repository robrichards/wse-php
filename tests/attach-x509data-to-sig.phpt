--TEST--
WSSESoap attachX509DatatoSig adds IssuerSerial KeyInfo
--FILE--
<?php
require dirname(__FILE__) . '/../wse-php.php';
use RobRichards\WsePhp\WSSESoap;
use RobRichards\XMLSecLibs\XMLSecurityKey;

$priv = dirname(__FILE__) . '/fixtures/privkey.pem';

$doc = new DOMDocument();
$doc->loadXML('<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Header/><soap:Body><ping>1</ping></soap:Body></soap:Envelope>');
$wsse = new WSSESoap($doc);

$signKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA1, array('type' => 'private'));
$signKey->loadKey($priv, true);
$wsse->signSoapDoc($signKey, array('insertBefore' => true));

$issuerName = 'CN=test.example, O=Example Org, C=US';
$serialNumber = '123456789';
$wsse->attachX509DatatoSig(array(
    'KeyInfo' => array(
        'X509Data' => array(
            'IssuerName' => $issuerName,
            'SerialNumber' => $serialNumber,
        ),
    ),
));

$xml = $wsse->saveXML();
echo (strpos($xml, 'X509IssuerSerial') !== false ? 'ISSUER_SERIAL_OK' : 'ISSUER_SERIAL_FAIL')."\n";
echo (strpos($xml, htmlspecialchars($issuerName, ENT_QUOTES)) !== false || strpos($xml, $issuerName) !== false ? 'ISSUER_NAME_OK' : 'ISSUER_NAME_FAIL')."\n";
echo (strpos($xml, $serialNumber) !== false ? 'SERIAL_OK' : 'SERIAL_FAIL')."\n";
echo (strpos($xml, 'SecurityTokenReference') !== false ? 'STR_OK' : 'STR_FAIL')."\n";
?>
--EXPECTF--
ISSUER_SERIAL_OK
ISSUER_NAME_OK
SERIAL_OK
STR_OK
