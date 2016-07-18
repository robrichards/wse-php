<?php
require __DIR__ . '/../vendor/autoload.php';

use RobRichards\WsePhp\WSASoap;
use RobRichards\WsePhp\WSSESoap;
use RobRichards\XMLSecLibs\XMLSecurityKey;

define('PRIVATE_KEY', 'pk-private_key.pem');
define('CERT_FILE', 'cert-public_key.pem');

class MySoap extends SoapClient
{

    function __doRequest($request, $location, $saction, $version)
    {
        $dom = new DOMDocument();
        $dom->loadXML($request);

        $objWSA = new WSASoap($dom);
        $objWSA->addAction($saction);
        $objWSA->addTo($location);
        $objWSA->addMessageID();
        $objWSA->addReplyTo();

        $dom = $objWSA->getDoc();

        $objWSSE = new WSSESoap($dom);
        /* Sign all headers to include signing the WS-Addressing headers */
        $objWSSE->signAllHeaders = true;

        $objWSSE->addTimestamp();

        /* create new XMLSec Key using RSA SHA-1 and type is private key */
        $objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA1, array('type' => 'private'));

        /* load the private key from file - last arg is bool if key in file (true) or is string (FALSE) */
        $objKey->loadKey(PRIVATE_KEY, true);

        /* Sign the message - also signs appropraite WS-Security items */
        $objWSSE->signSoapDoc($objKey);

        /* Add certificate (BinarySecurityToken) to the message and attach pointer to Signature */
        $token = $objWSSE->addBinaryToken(file_get_contents(CERT_FILE));
        $objWSSE->attachTokentoSig($token);

        $request = $objWSSE->saveXML();
        return parent::__doRequest($request, $location, $saction, $version);
    }
}

$wsdl = '<wsdl location>';

$sc = new MySoap($wsdl);

try {
    $out = $sc->callmethod(1);
    var_dump($out);
} catch (SoapFault $fault) {
    var_dump($fault);
}

