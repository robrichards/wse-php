<?php
require('soap-wsse.php');

define('PRIVATE_KEY', 'priv_key.pem');
define('CERT_FILE', 'pub_key.pem');
define('SERVICE_CERT', 'sitekey_pub.cer');

class mySoap extends SoapClient {

    function __doRequest($request, $location, $saction, $version) {
		$doc = new DOMDocument('1.0');
		$doc->loadXML($request);
		
		$objWSSE = new WSSESoap($doc);
		$objWSSE = new WSSESoap($this->soapDoc);
		$objWSSE->signAllHeaders = true;
		
		
		// creating symmetrical key, encrypt it with certificate and adding to header
		$symmetricKey = new XMLSecurityKey(XMLSecurityKey::AES128_CBC);
		$symmetricKey->generateSessionKey();
		
		$siteKey = new XMLSecurityKey(XMLSecurityKey::RSA_1_5, array('type'=>'public'));
		$siteKey->loadKey($this->server_certificate, false, true);
		
		$encryptedKey = new XMLSecEnc();
		$encryptedKey->encryptKey($siteKey, $symmetricKey, false);
		
		// creating derived key token for signature
		$signKey = $objWSSE->createDKT($symmetricKey, XMLSecurityKey::HMAC_SHA1/*, 160*/);
		
		// creating derived key token for encryption
		$encryptKey = $objWSSE->createDKT($symmetricKey, XMLSecurityKey::AES128_CBC);
		
		$options = array('insertBefore' => false);
		$objWSSE->signSoapDoc($signKey, $options);
		
		$token = $objWSSE->addBinaryToken($this->client_certificate);
		
		$options = array("KeyInfo" => array("ThumbprintSHA1" => TRUE));
		$objWSSE->addEncryptedKey($signode, $encryptedKey, $siteKey, $options);
		$objWSSE->addTimestamp(300);
		
		$objWSSE->encryptSoapDocDKT($encryptKey, NULL, array('FfeHeader'));
		
		$objWSSE->addDKT($signKey, 'Signature');
		$objWSSE->addDKT($encryptKey, 'EncryptedData');
		
		$signKey2 = new XMLSecurityKey(XMLSecurityKey::RSA_SHA1, array('type'=>'private'));
		$signKey2->loadKey($this->private_key_text, false);
		
		$options =array('insertBefore' => false/*, "KeyInfo" => array("X509SubjectKeyIdentifier" => TRUE)*/);
		$objWSSE->signSignature($signKey2, $options);
		$objWSSE->attachTokentoSig($token, 1);
		
		$objWSSE->finalChangesDKT();
		
		return parent::__doRequest($objWSSE->saveXML(), $location, $saction, $version);
	}
}

$wsdl = <wsdl location>;

$sc = new mySoap($wsdl);

try {
	$out = $sc->callmethod(1);
	var_dump($out);
} catch (SoapFault $fault) {
	var_dump($fault);
}