<?php
require __DIR__ . '/../vendor/autoload.php';

use RobRichards\WsePhp\WSSESoap;
use RobRichards\WsePhp\WSSESoapServer;
use RobRichards\XMLSecLibs\XMLSecurityKey;

/*
 * Server-side counterpart to soap-sign-encrypt.php.
 *
 * Configure paths to your key material:
 * - SERVER_PRIVATE_KEY: decrypt incoming messages and sign responses
 * - SERVER_CERT: BinarySecurityToken attached to outgoing signatures
 * - CLIENT_CERT: caller public certificate used to encrypt responses
 *
 * Incoming messages must include a BinarySecurityToken (or other KeyInfo the
 * server can resolve) so WSSESoapServer can verify the signature after decrypt.
 *
 * Pass false for encryptSoapDoc()'s $encryptSignature argument so the Signature
 * stays in the clear while the Body is encrypted. That allows verification after
 * decryptSoapDoc(). The client in soap-sign-encrypt.php must use the same setting.
 */

define('SERVER_PRIVATE_KEY', 'server_priv_key.pem');
define('SERVER_CERT', 'server_pub_key.pem');
define('CLIENT_CERT', 'client_pub_key.pem');

class SecureSoapServer extends SoapServer
{
    private function decryptRequest(string $request): string
    {
        $doc = new DOMDocument('1.0');
        $doc->loadXML($request);

        $objWSSE = new WSSESoap($doc);
        $options = array(
            'keys' => array(
                'private' => array(
                    'key' => SERVER_PRIVATE_KEY,
                    'isFile' => true,
                    'isCert' => false,
                ),
            ),
        );
        $objWSSE->decryptSoapDoc($doc, $options);

        $objServer = new WSSESoapServer($doc);
        if (!$objServer->process()) {
            throw new Exception('WS-Security signature verification failed');
        }

        /* Optional: identify the caller, e.g. $objServer->getSigningKey()?->getX509Thumbprint() */

        return $objServer->saveXML();
    }

    private function secureResponse(string $response): string
    {
        $doc = new DOMDocument('1.0');
        $doc->loadXML($response);

        $objWSSE = new WSSESoap($doc);
        $objWSSE->addTimestamp();

        $objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA1, array('type' => 'private'));
        $objKey->loadKey(SERVER_PRIVATE_KEY, true);
        $objWSSE->signSoapDoc($objKey, array('insertBefore' => false));

        $token = $objWSSE->addBinaryToken(file_get_contents(SERVER_CERT));
        $objWSSE->attachTokentoSig($token);

        $sessionKey = new XMLSecurityKey(XMLSecurityKey::AES256_CBC);
        $sessionKey->generateSessionKey();

        $clientKey = new XMLSecurityKey(XMLSecurityKey::RSA_OAEP_MGF1P, array('type' => 'public'));
        $clientKey->loadKey(CLIENT_CERT, true, true);

        $options = array('KeyInfo' => array('X509SubjectKeyIdentifier' => true));
        $objWSSE->encryptSoapDoc($clientKey, $sessionKey, $options, false);

        return $objWSSE->saveXML();
    }

    public function handle($request = null)
    {
        if ($request === null) {
            $request = file_get_contents('php://input');
        }

        try {
            $cleartextRequest = $this->decryptRequest($request);
        } catch (Exception $e) {
            header('HTTP/1.1 500 Internal Server Error');
            header('Content-Type: text/plain; charset=utf-8');
            echo $e->getMessage();

            return;
        }

        ob_start();
        parent::handle($cleartextRequest);
        $cleartextResponse = ob_get_clean();

        try {
            $securedResponse = $this->secureResponse($cleartextResponse);
        } catch (Exception $e) {
            header('HTTP/1.1 500 Internal Server Error');
            header('Content-Type: text/plain; charset=utf-8');
            echo $e->getMessage();

            return;
        }

        header('Content-Type: text/xml; charset=utf-8');
        header('Content-Length: '.strlen($securedResponse));
        echo $securedResponse;
    }
}

$wsdl = '<wsdl location>';

$server = new SecureSoapServer($wsdl);
$server->handle();
