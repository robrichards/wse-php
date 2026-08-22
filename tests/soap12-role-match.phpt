--TEST--
SOAP 1.2 Security header role attribute is matched
--FILE--
<?php
require dirname(__FILE__) . '/../wse-php.php';
use RobRichards\WsePhp\WSSESoap;

$xml = <<<XML
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
  <soap:Header>
    <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" soap:role="urn:test:role"/>
  </soap:Header>
  <soap:Body/>
</soap:Envelope>
XML;
$doc = new DOMDocument();
$doc->loadXML($xml);
$wsse = new WSSESoap($doc, true, 'urn:test:role');
$wsse->addTimestamp(60);
$nodes = $doc->getElementsByTagNameNS('http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd', 'Security');
echo $nodes->length."\n";
?>
--EXPECTF--
1
