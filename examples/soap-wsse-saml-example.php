<?php
require __DIR__ . '/../vendor/autoload.php';

use RobRichards\WsePhp\WSSESoap;
use RobRichards\XMLSecLibs\XMLSecurityKey;

define('PRIVATE_KEY', 'priv_key.pem');
define('CERT_FILE', 'pub_key.pem');
define('SERVICE_CERT', 'sitekey_pub.cer');

class MySoap extends SoapClient
{
    /**
     * @var string
     */
    public $samlToken;
    

    public function __doRequest($request, $location, $saction, $version)
    {
        $doc = new DOMDocument('1.0');
        $doc->loadXML($request);

        $objWSSE = new WSSESoap($doc);

        /* add Timestamp with no expiration timestamp */
        $objWSSE->signAllHeaders = true;
        $objWSSE->signBody = true;
        $objWSSE->addTimestamp();

        /* create new XMLSec Key using AES256_CBC and type is private key */
        $objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA1, array('type' => 'private'));

        /* load the private key from file - last arg is bool if key in file (true) or is string (false) */
        $objKey->loadKey(PRIVATE_KEY, true);

        /* Sign the message - also signs appropiate WS-Security items */
        $options = array("insertBefore" => false);
        $objWSSE->signSoapDoc($objKey, $options);

        /* Add SAML Token to the message */
        $token = $objWSSE->addSamlToken($this->samlToken);

        /* Attach pointer to Signature */
        $objWSSE->attachTokentoSig($token, true);

        $request = $objWSSE->saveXML();
        
        $retVal = parent::__doRequest($request, $location, $saction, $version);

        return $retVal;
    }
}

$wsdl = '<wsdl location>';

$sc = new MySoap($wsdl);
$sc->samlToken = '<SAML_TOKEN>';

try {
    $out = $sc->callmethod(1);
    var_dump($out);
} catch (SoapFault $fault) {
    var_dump($fault);
}

