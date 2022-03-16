<?php
require __DIR__ . '/../vendor/autoload.php';

use RobRichards\WsePhp\WSSESoap;
use RobRichards\XMLSecLibs\XMLSecurityKey;

define('PRIVATE_KEY', 'pk-private_key.pem');
define('CERT_FILE', 'cert-public_key.pem');

class MySoap extends SoapClient
{

    /** @var string $username */
    private string $username;

    /** @var null|string $password */
    private ?string $password;

    /** @var bool $digest */
    private bool $digest;

    /** @var bool $addNonce */
    private bool $addNonce;

    /** @var bool $addCreated */
    private bool $addCreated;

    /**
     * addUserToken
     *
     * @param string $username
     * @param null|string $password
     * @param bool $digest
     * @param bool $addNonce
     * @param bool $addCreated
     *
     * @return void
     */
    public function addUserToken(
        string $username,
        ?string $password = null,
        bool $digest = false,
        bool $addNonce = true,
        bool $addCreated = true
    ): void {
        $this->username = $username;
        $this->password = $password;
        $this->digest = $digest;
        $this->addNonce = $addNonce;
        $this->addCreated = $addCreated;
    }

    public function __doRequest($request, $location, $saction, $version, $one_way = 0)
    {
        $doc = new DOMDocument('1.0');
        $doc->loadXML($request);

        $objWSSE = new WSSESoap($doc);

        /* Sign all headers to include signing the WS-Addressing headers */
        $objWSSE->signAllHeaders = true;

        $objWSSE->addTimestamp();
        $objWSSE->addUserToken($this->username, $this->password, $this->digest, $this->addNonce, $this->addCreated);

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

$sClient = new MySoap($wsdl);
$sClient->addUserToken('<username>', '<password>');

try {
    $out = $sClient->callmethod(1);
    var_dump($out);
} catch (SoapFault $fault) {
    var_dump($fault);
}
