<?php  
/** 
 * soap-wsse.php 
 * 
 * Copyright (c) 2010, Robert Richards <rrichards@ctindustries.net>. 
 * All rights reserved. 
 * 
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions 
 * are met: 
 * 
 *   * Redistributions of source code must retain the above copyright 
 *     notice, this list of conditions and the following disclaimer. 
 * 
 *   * Redistributions in binary form must reproduce the above copyright 
 *     notice, this list of conditions and the following disclaimer in 
 *     the documentation and/or other materials provided with the 
 *     distribution. 
 * 
 *   * Neither the name of Robert Richards nor the names of his 
 *     contributors may be used to endorse or promote products derived 
 *     from this software without specific prior written permission. 
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS 
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE 
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, 
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, 
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER 
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT 
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN 
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
 * POSSIBILITY OF SUCH DAMAGE. 
 * 
 * @author     Robert Richards <rrichards@ctindustries.net> 
 * @copyright  2007-2015 Robert Richards <rrichards@ctindustries.net> 
 * @license    http://www.opensource.org/licenses/bsd-license.php  BSD License 
 * @version    1.1.1-dev
 */ 
  
require('xmlseclibs.php'); 

class WSSESoap { 
    const WSSENS = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd'; 
    const WSUNS = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd'; 
    const WSUNAME = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0'; 
    const WSSEPFX = 'wsse'; 
    const WSUPFX = 'wsu'; 
    private $soapNS, $soapPFX; 
    private $soapDoc = NULL; 
    private $envelope = NULL; 
    private $SOAPXPath = NULL; 
    private $secNode = NULL; 
    public $signAllHeaders = FALSE;
    public $signBody = TRUE;
     
    private function locateSecurityHeader($bMustUnderstand = TRUE, $setActor = NULL) { 
        if ($this->secNode == NULL) { 
            $headers = $this->SOAPXPath->query('//wssoap:Envelope/wssoap:Header'); 
            $header = $headers->item(0); 
            if (! $header) { 
                $header = $this->soapDoc->createElementNS($this->soapNS, $this->soapPFX.':Header'); 
                $this->envelope->insertBefore($header, $this->envelope->firstChild); 
            } 
            $secnodes = $this->SOAPXPath->query('./wswsse:Security', $header); 
            $secnode = NULL; 
            foreach ($secnodes AS $node) { 
                $actor = $node->getAttributeNS($this->soapNS, 'actor'); 
                if ($actor == $setActor) { 
                    $secnode = $node; 
                    break; 
                } 
            } 
            if (! $secnode) { 
                $secnode = $this->soapDoc->createElementNS(WSSESoap::WSSENS, WSSESoap::WSSEPFX.':Security'); 
                $header->appendChild($secnode); 
                if ($bMustUnderstand) { 
                    $secnode->setAttributeNS($this->soapNS, $this->soapPFX.':mustUnderstand', '1'); 
                } 
                if (! empty($setActor)) { 
                    $ename = 'actor'; 
                    if ($this->soapNS == 'http://www.w3.org/2003/05/soap-envelope') { 
                        $ename = 'role'; 
                    } 
                    $secnode->setAttributeNS($this->soapNS, $this->soapPFX.':'.$ename, $setActor); 
                } 
            } 
            $this->secNode = $secnode; 
        } 
        return $this->secNode; 
    } 

    public function __construct($doc, $bMustUnderstand = TRUE, $setActor=NULL) { 
        $this->soapDoc = $doc; 
        $this->envelope = $doc->documentElement; 
        $this->soapNS = $this->envelope->namespaceURI; 
        $this->soapPFX = $this->envelope->prefix; 
        $this->SOAPXPath = new DOMXPath($doc); 
        $this->SOAPXPath->registerNamespace('wssoap', $this->soapNS); 
        $this->SOAPXPath->registerNamespace('wswsse', WSSESoap::WSSENS); 
        $this->locateSecurityHeader($bMustUnderstand, $setActor); 
    } 

    public function addTimestamp($secondsToExpire=3600) { 
        /* Add the WSU timestamps */ 
        $security = $this->locateSecurityHeader(); 

        $timestamp = $this->soapDoc->createElementNS(WSSESoap::WSUNS, WSSESoap::WSUPFX.':Timestamp'); 
        $security->insertBefore($timestamp, $security->firstChild); 
        $currentTime = time(); 
        $created = $this->soapDoc->createElementNS(WSSESoap::WSUNS,  WSSESoap::WSUPFX.':Created', gmdate("Y-m-d\TH:i:s", $currentTime).'Z'); 
        $timestamp->appendChild($created); 
        if (! is_null($secondsToExpire)) { 
            $expire = $this->soapDoc->createElementNS(WSSESoap::WSUNS,  WSSESoap::WSUPFX.':Expires', gmdate("Y-m-d\TH:i:s", $currentTime + $secondsToExpire).'Z'); 
            $timestamp->appendChild($expire); 
        } 
    } 

    public function addUserToken($userName, $password=NULL, $passwordDigest=FALSE) { 
        if ($passwordDigest && empty($password)) { 
            throw new Exception("Cannot calculate the digest without a password"); 
        } 
         
        $security = $this->locateSecurityHeader(); 

        $token = $this->soapDoc->createElementNS(WSSESoap::WSSENS, WSSESoap::WSSEPFX.':UsernameToken'); 
        $security->insertBefore($token, $security->firstChild); 

        $username = $this->soapDoc->createElementNS(WSSESoap::WSSENS,  WSSESoap::WSSEPFX.':Username', $userName); 
        $token->appendChild($username); 
         
        /* Generate nonce - create a 256 bit session key to be used */ 
        $objKey = new XMLSecurityKey(XMLSecurityKey::AES256_CBC); 
        $nonce = $objKey->generateSessionKey(); 
        unset($objKey); 
        $createdate = gmdate("Y-m-d\TH:i:s").'Z'; 
         
        if ($password) { 
            $passType = WSSESoap::WSUNAME.'#PasswordText'; 
            if ($passwordDigest) { 
                $password = base64_encode(sha1($nonce.$createdate. $password, true)); 
                $passType = WSSESoap::WSUNAME.'#PasswordDigest'; 
            } 
            $passwordNode = $this->soapDoc->createElementNS(WSSESoap::WSSENS,  WSSESoap::WSSEPFX.':Password', $password); 
            $token->appendChild($passwordNode); 
            $passwordNode->setAttribute('Type', $passType); 
        } 

        $nonceNode = $this->soapDoc->createElementNS(WSSESoap::WSSENS,  WSSESoap::WSSEPFX.':Nonce', base64_encode($nonce)); 
        $token->appendChild($nonceNode); 

        $created = $this->soapDoc->createElementNS(WSSESoap::WSUNS,  WSSESoap::WSUPFX.':Created', $createdate); 
        $token->appendChild($created); 
    } 

    public function addBinaryToken($cert, $isPEMFormat=TRUE, $isDSig=TRUE) { 
        $security = $this->locateSecurityHeader(); 
        $data = XMLSecurityDSig::get509XCert($cert, $isPEMFormat); 

        $token = $this->soapDoc->createElementNS(WSSESoap::WSSENS, WSSESoap::WSSEPFX.':BinarySecurityToken', $data); 
        $security->insertBefore($token, $security->firstChild); 

        $token->setAttribute('EncodingType', 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary'); 
        $token->setAttributeNS(WSSESoap::WSUNS, WSSESoap::WSUPFX.':Id', XMLSecurityDSig::generate_GUID()); 
        $token->setAttribute('ValueType', 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3'); 
         
        return $token; 
    } 
     
    public function attachTokentoSig($token, $pos=0) { 
        if (! ($token instanceof DOMElement)) { 
            throw new Exception('Invalid parameter: BinarySecurityToken element expected'); 
        } 
        $objXMLSecDSig = new XMLSecurityDSig(); 
        if ($objDSig = $objXMLSecDSig->locateSignature($this->soapDoc, $pos)) { 
            $tokenURI = '#'.$token->getAttributeNS(WSSESoap::WSUNS, "Id"); 
            $this->SOAPXPath->registerNamespace('secdsig', XMLSecurityDSig::XMLDSIGNS); 
            $query = "./secdsig:KeyInfo"; 
            $nodeset = $this->SOAPXPath->query($query, $objDSig); 
            $keyInfo = $nodeset->item(0); 
            if (! $keyInfo) { 
                $keyInfo = $objXMLSecDSig->createNewSignNode('KeyInfo'); 
                $objDSig->appendChild($keyInfo); 
            } 
             
            $tokenRef = $this->soapDoc->createElementNS(WSSESoap::WSSENS, WSSESoap::WSSEPFX.':SecurityTokenReference'); 
            $keyInfo->appendChild($tokenRef); 
            $reference = $this->soapDoc->createElementNS(WSSESoap::WSSENS, WSSESoap::WSSEPFX.':Reference');
            $reference->setAttribute('ValueType', 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3');
            $reference->setAttribute("URI", $tokenURI); 
            $tokenRef->appendChild($reference); 
        } else { 
            throw new Exception('Unable to locate digital signature'); 
        } 
    } 

    public function signSoapDoc($objKey, $options = NULL) {
        $objDSig = new XMLSecurityDSig(); 

        $objDSig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N); 

        $arNodes = array(); 
        foreach ($this->secNode->childNodes AS $node) { 
            if ($node->nodeType == XML_ELEMENT_NODE) { 
                $arNodes[] = $node; 
            } 
        } 

        if ($this->signAllHeaders) { 
            foreach ($this->secNode->parentNode->childNodes AS $node) { 
                if (($node->nodeType == XML_ELEMENT_NODE) &&  
                ($node->namespaceURI != WSSESoap::WSSENS)) { 
                    $arNodes[] = $node; 
                } 
            } 
        } 

        if ($this->signBody) {
	        foreach ($this->envelope->childNodes AS $node) { 
	            if ($node->namespaceURI == $this->soapNS && $node->localName == 'Body') { 
	                $arNodes[] = $node; 
	                break; 
	            } 
	        }
        }
        
        $algorithm = XMLSecurityDSig::SHA1;
        if (is_array($options) && isset($options["algorithm"])) {
            $algorithm = $options["algorithm"];
        }
        
        $arOptions = array('prefix'=>WSSESoap::WSUPFX, 'prefix_ns'=>WSSESoap::WSUNS); 
        $objDSig->addReferenceList($arNodes, $algorithm, NULL, $arOptions); 

        $objDSig->sign($objKey); 

        $insertTop = TRUE;
        if (is_array($options) && isset($options["insertBefore"])) {
            $insertTop = (bool)$options["insertBefore"];
        }
        $objDSig->appendSignature($this->secNode, $insertTop);

/* New suff */
        if (is_array($options)) {
            if (! empty($options["KeyInfo"]) ) {
                if (! empty($options["KeyInfo"]["X509SubjectKeyIdentifier"])) {
                    $sigNode = $this->secNode->firstChild->nextSibling;
                    $objDoc = $sigNode->ownerDocument;
                    $keyInfo = $sigNode->ownerDocument->createElementNS(XMLSecurityDSig::XMLDSIGNS, 'ds:KeyInfo');
                    $sigNode->appendChild($keyInfo);
				    $tokenRef = $objDoc->createElementNS(WSSESoap::WSSENS, WSSESoap::WSSEPFX . ':SecurityTokenReference');
				    $keyInfo->appendChild($tokenRef);
				    $reference = $objDoc->createElementNS(WSSESoap::WSSENS, WSSESoap::WSSEPFX . ':KeyIdentifier');
				    $reference->setAttribute("ValueType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier");
				    $reference->setAttribute("EncodingType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary");
                    $tokenRef->appendChild($reference);
					$x509 = openssl_x509_parse($objKey->getX509Certificate());
					$keyid = $x509["extensions"]["subjectKeyIdentifier"];
					$arkeyid = split(":", $keyid);
					$data = "";
					foreach ($arkeyid AS $hexchar) {
					    $data .= chr(hexdec($hexchar));
					}
					$dataNode = new DOMText(base64_encode($data));
					$reference->appendChild($dataNode);
                }
            }
        }
    }

    public function addEncryptedKey($node, $key, $token, $options = NULL) {
        if (! $key->encKey) { 
            return FALSE; 
        } 
        $encKey = $key->encKey; 
        $security = $this->locateSecurityHeader(); 
        $doc = $security->ownerDocument; 
        if (! $doc->isSameNode($encKey->ownerDocument)) { 
            $key->encKey = $security->ownerDocument->importNode($encKey, TRUE); 
            $encKey = $key->encKey; 
        } 
        if (! empty($key->guid)) { 
            return TRUE; 
        } 
         
        $lastToken = NULL; 
        $findTokens = $security->firstChild; 
        while ($findTokens) { 
            if ($findTokens->localName == 'BinarySecurityToken') { 
                $lastToken = $findTokens; 
            } 
            $findTokens = $findTokens->nextSibling; 
        } 
        if ($lastToken) { 
            $lastToken = $lastToken->nextSibling; 
        } 

        $security->insertBefore($encKey, $lastToken); 
        $key->guid = XMLSecurityDSig::generate_GUID(); 
        $encKey->setAttribute('Id', $key->guid); 
        $encMethod = $encKey->firstChild; 
        while ($encMethod && $encMethod->localName != 'EncryptionMethod') { 
            $encMethod = $encMethod->nextChild; 
        } 
        if ($encMethod) { 
            $encMethod = $encMethod->nextSibling; 
        } 
        $objDoc = $encKey->ownerDocument; 
        $keyInfo = $objDoc->createElementNS('http://www.w3.org/2000/09/xmldsig#', 'dsig:KeyInfo'); 
        $encKey->insertBefore($keyInfo, $encMethod); 
        $tokenRef = $objDoc->createElementNS(WSSESoap::WSSENS, WSSESoap::WSSEPFX.':SecurityTokenReference'); 
        $keyInfo->appendChild($tokenRef); 
/* New suff */
        if (is_array($options)) {
            if (! empty($options["KeyInfo"]) ) {
                if (! empty($options["KeyInfo"]["X509SubjectKeyIdentifier"])) {
				    $reference = $objDoc->createElementNS(WSSESoap::WSSENS, WSSESoap::WSSEPFX . ':KeyIdentifier');
				    $reference->setAttribute("ValueType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier");
				    $reference->setAttribute("EncodingType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary");
				    $tokenRef->appendChild($reference);
					$x509 = openssl_x509_parse($token->getX509Certificate());
					$keyid = $x509["extensions"]["subjectKeyIdentifier"];
					$arkeyid = split(":", $keyid);
					$data = "";
					foreach ($arkeyid AS $hexchar) {
					    $data .= chr(hexdec($hexchar));
					}
					$dataNode = new DOMText(base64_encode($data));
					$reference->appendChild($dataNode);
                    return TRUE;
                }
                if (! empty($options["KeyInfo"]["ThumbprintSHA1"])) {
                    $reference = $objDoc->createElementNS(WSSESoap::WSSENS, WSSESoap::WSSEPFX . ':KeyIdentifier');
                    $reference->setAttribute("ValueType", "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#ThumbprintSHA1");
                    $reference->setAttribute("EncodingType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary");
                    $tokenRef->appendChild($reference);
                        $data = $token->getX509Thumbprint();
                        $dataNode = new DOMText(base64_encode($data));
                        $reference->appendChild($dataNode);
                    return TRUE;
                }
            }
        }
        
        $tokenURI = '#'.$token->getAttributeNS(WSSESoap::WSUNS, "Id");
        $reference = $objDoc->createElementNS(WSSESoap::WSSENS, WSSESoap::WSSEPFX.':Reference'); 
        $reference->setAttribute("URI", $tokenURI); 
        $tokenRef->appendChild($reference); 

        return TRUE; 
    } 

    public function AddReference($baseNode, $guid) { 
        $refList = NULL; 
        $child = $baseNode->firstChild; 
        while($child) { 
            if (($child->namespaceURI == XMLSecEnc::XMLENCNS) && ($child->localName == 'ReferenceList')) { 
                $refList = $child; 
                break; 
            } 
            $child = $child->nextSibling; 
        } 
        $doc = $baseNode->ownerDocument; 
        if (is_null($refList)) { 
            $refList = $doc->createElementNS(XMLSecEnc::XMLENCNS, 'xenc:ReferenceList'); 
            $baseNode->appendChild($refList); 
        } 
        $dataref = $doc->createElementNS(XMLSecEnc::XMLENCNS, 'xenc:DataReference'); 
        $refList->appendChild($dataref); 
        $dataref->setAttribute('URI', '#'.$guid); 
    } 

    public function EncryptBody($siteKey, $objKey, $token, $options=array()) { 

        $enc = new XMLSecEnc(); 
        foreach ($this->envelope->childNodes AS $node) { 
            if ($node->namespaceURI == $this->soapNS && $node->localName == 'Body') { 
                break; 
            } 
        } 
        $enc->setNode($node); 
        /* encrypt the symmetric key */ 
        $enc->encryptKey($siteKey, $objKey, FALSE); 

        $enc->type = XMLSecEnc::Content; 
        /* Using the symmetric key to actually encrypt the data */ 
        $encNode = $enc->encryptNode($objKey); 

        $guid = XMLSecurityDSig::generate_GUID(); 
        $encNode->setAttribute('Id', $guid); 

        $refNode = $encNode->firstChild; 
        while($refNode && $refNode->nodeType != XML_ELEMENT_NODE) { 
            $refNode = $refNode->nextSibling; 
        } 
        if ($refNode) { 
            $refNode = $refNode->nextSibling; 
        } 
        if ($this->addEncryptedKey($encNode, $enc, $token, $options)) { 
            $this->AddReference($enc->encKey, $guid); 
        } 
    } 
     
    public function encryptSoapDoc($siteKey, $objKey, $options=NULL, $encryptSignature=TRUE) {

		$enc = new XMLSecEnc();

		$xpath = new DOMXPath($this->envelope->ownerDocument);
		if ($encryptSignature ==  FALSE) {
			$nodes = $xpath->query('//*[local-name()="Body"]');
		} else {
			$nodes = $xpath->query('//*[local-name()="Signature"] | //*[local-name()="Body"]');
		}
		
		foreach ($nodes AS $node) {
			$type = XMLSecEnc::Element;
			$name = $node->localName;
			if ($name == "Body") {
				$type = XMLSecEnc::Content;
			}
			$enc->addReference($name, $node, $type);
		}

		$enc->encryptReferences($objKey);
		
		$enc->encryptKey($siteKey, $objKey, false);
		
		$nodes = $xpath->query('//*[local-name()="Security"]');
		$signode = $nodes->item(0);
		$this->addEncryptedKey($signode, $enc, $siteKey, $options);
    }
    
    public function decryptSoapDoc($doc, $options) {

		$privKey = NULL;
		$privKey_isFile = FALSE;
		$privKey_isCert = FALSE;
		
		if (is_array($options)) {
			$privKey = (! empty($options["keys"]["private"]["key"]) ? $options["keys"]["private"]["key"] : NULL);
			$privKey_isFile = (! empty($options["keys"]["private"]["isFile"]) ? TRUE : FALSE);
			$privKey_isCert = (! empty($options["keys"]["private"]["isCert"])  ? TRUE : FALSE);
		}
		
		$objenc = new XMLSecEnc();

		$xpath = new DOMXPath($doc);
		$envns = $doc->documentElement->namespaceURI;
		$xpath->registerNamespace("soapns", $envns);
		$xpath->registerNamespace("soapenc", "http://www.w3.org/2001/04/xmlenc#");
		$xpath->registerNamespace("wcs", "http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512"); // ADDED BY ME
		$xpath->registerNamespace("xenc", XMLSecEnc::XMLENCNS);
		
		$nodes = $xpath->query('/soapns:Envelope/soapns:Header/*[local-name()="Security"]/soapenc:EncryptedKey');

		$references = array();
		if ($node = $nodes->item(0)) {
			$objenc = new XMLSecEnc();
			$objenc->setNode($node);
		    if (! $objKey = $objenc->locateKey()) {
		        throw new Exception("Unable to locate algorithm for this Encrypted Key");
		    }
		    $objKey->isEncrypted = TRUE;
		    $objKey->encryptedCtx = $objenc;
		    XMLSecEnc::staticLocateKeyInfo($objKey, $node);
			if ($objKey && $objKey->isEncrypted) {
				$objencKey = $objKey->encryptedCtx;
				$objKey->loadKey($privKey, $privKey_isFile, $privKey_isCert);
				$key = $objencKey->decryptKey($objKey);
				$objKey->loadKey($key);
			}

			$refnodes = $xpath->query('./soapenc:ReferenceList/soapenc:DataReference/@URI', $node);
			foreach ($refnodes as $reference) {
				$references[] = $reference->nodeValue;
			}
		} else {
			$nodes2 = $xpath->query('/soapns:Envelope/soapns:Header/*[local-name()="Security"]/wcs:DerivedKeyToken');
			if ($node = $nodes2->item(0)) {
				$refnodes = $xpath->query('/soapns:Envelope/soapns:Header/*[local-name()="Security"]/*[local-name()="ReferenceList"]/*[local-name()="DataReference"]/@URI');
				foreach ($refnodes as $reference) {
					$references[] = $reference->nodeValue;
				}
				$nonces = $xpath->query('//*[local-name()="Nonce"]');
				if($nonce = $nonces->item(0)) {
					$seed = 'WS-SecureConversation'.'WS-SecureConversation'.base64_decode($nonce->nodeValue);
					$key = $this->psha1($privKey, $seed);
				}
			}
		}

		foreach ($references AS $reference) {
			$arUrl = parse_url($reference);
			$reference = $arUrl['fragment'];
			$query = '//*[@Id="'.$reference.'"]';
			$nodes = $xpath->query($query);
			$encData = $nodes->item(0);

			if ($algo = $xpath->evaluate("string(./soapenc:EncryptionMethod/@Algorithm)", $encData)) {
				$objKey = new XMLSecurityKey($algo);
				$objKey->loadKey($key);
			} else if ($algo = $xpath->evaluate("string(./xenc:EncryptionMethod/@Algorithm)", $encData)) { // ADDED BY ME -->
				$objKey = new XMLSecurityKey($algo);
				$objKey->loadKey($key);
			}

			$objenc->setNode($encData);
			$objenc->type = $encData->getAttribute("Type");
			$decrypt = $objenc->decryptNode($objKey, TRUE);
		}
		
		return TRUE;
    }

	public function createDKT($symmetricKey, $encTypeDKT, $sizeBits = 128) {
		$objKey = new XMLSecurityKey($symmetricKey->type, array('type'=>'private')); 
		$nonceValue = $objKey->generateSessionKey($encType);
		$seed = 'WS-SecureConversation'.'WS-SecureConversation'.$nonceValue;
		$newKeyValue = $this->psha1($symmetricKey->key, $seed, $sizeBits);

		$newKey = new XMLSecurityKey($encTypeDKT, array('type'=>'private'));
		$newKey->loadKey($newKeyValue);
		$newKey->nonce = base64_encode($nonceValue);

		return $newKey;
	}
    
	public function addDKT($key, $refNodeName) {
		$xpath = new DOMXPath($this->envelope->ownerDocument);
		$nodes = $xpath->query('//*[local-name()="EncryptedKey"]');
		$encKeyNode = $nodes->item(0);
		$tokenURI = '#'.$encKeyNode->getAttribute('Id'); 

		$dktId = XMLSecurityDSig::generate_GUID();
		$dkt = $this->soapDoc->createElementNS('http://schemas.xmlsoap.org/ws/2005/02/sc', 'dkt:DerivedKeyToken');
		$dkt->setAttributeNS(WSSESoap::WSUNS, WSSESoap::WSUPFX.':Id', $dktId);
		$tokenRef = $this->soapDoc->createElementNS(WSSESoap::WSSENS, WSSESoap::WSSEPFX.':SecurityTokenReference');
		$tokenRef->setAttributeNS("http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd", "ttype:TokenType", 'http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#EncryptedKey');
		$reference = $this->soapDoc->createElementNS(WSSESoap::WSSENS, WSSESoap::WSSEPFX.':Reference');
		$reference->setAttribute("URI", $tokenURI);
		$reference->setAttribute("ValueType", 'http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#EncryptedKey');
		$tokenRef->appendChild($reference);
		$dkt->appendChild($tokenRef);
		$dkt->appendChild($this->soapDoc->createElementNS('http://schemas.xmlsoap.org/ws/2005/02/sc', 'dkt:Offset', 0));
		$dkt->appendChild($this->soapDoc->createElementNS('http://schemas.xmlsoap.org/ws/2005/02/sc', 'dkt:Length', 16));
		$dkt->appendChild($this->soapDoc->createElementNS('http://schemas.xmlsoap.org/ws/2005/02/sc', 'dkt:Nonce', $key->nonce));
		$node = $encKeyNode->parentNode;
		$node->insertBefore($dkt, $node->lastChild);

		$refNodes = $xpath->query('//*[local-name()="'.$refNodeName.'"]');
		$refNodeIdsList = array();
		foreach ($refNodes as $refNode) {
			$keyInfo = $this->soapDoc->createElementNS(XMLSecurityDSig::XMLDSIGNS, 'KeyInfo');
			$refNode->appendChild($keyInfo);                
			$tokenRef = $this->soapDoc->createElementNS(WSSESoap::WSSENS, WSSESoap::WSSEPFX.':SecurityTokenReference'); 
			$keyInfo->appendChild($tokenRef); 
			$reference = $this->soapDoc->createElementNS(WSSESoap::WSSENS, WSSESoap::WSSEPFX.':Reference'); 
			$reference->setAttribute('ValueType', 'http://schemas.xmlsoap.org/ws/2005/02/sc/dk');
			$reference->setAttribute("URI", '#'.$dktId); 
			$tokenRef->appendChild($reference);
			$refNodeId = $refNode->getAttribute('Id');
			if ($refNodeId) {
				$refNodeIdsList[] = $refNodeId;
			}
		}
		if (!empty($refNodeIdsList)) {
			$referenceList = $this->soapDoc->createElementNS(XMLSecEnc::XMLENCNS, 'xenc:ReferenceList');
			foreach ($refNodeIdsList as $refNodeId) {
				$dataref = $this->soapDoc->createElementNS(XMLSecEnc::XMLENCNS, 'xenc:DataReference');
				$dataref->setAttribute('URI', '#'.$refNodeId);
				$referenceList->appendChild($dataref);         
			}
			$node->insertBefore($referenceList, $node->lastChild);
		}
    }
    
	public function finalChangesDKT() {
		$xpath = new DOMXPath($this->envelope->ownerDocument);
		$refNodes = $xpath->query('//*[local-name()="EncryptedData"]');
		$encData = $refNodes->item(0);
		$encHeader = $this->soapDoc->createElementNS('http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd', 'xench:EncryptedHeader');
		$encHeader->setAttribute("Id", $encData->getAttribute('Id'));
		$encData->removeAttribute("Id");
		$encData = $encData->parentNode->replaceChild($encHeader, $encData);

		$encHeader->appendChild($encData);
	}
    
	private function psha1($clientSecret, $serverSecret, $sizeBits = 128) {
		$sizeBytes = $sizeBits / 8;

		$hmacKey = $clientSecret;
		$hashSize = 160; // HMAC_SHA1 length is always 160
		$bufferSize = $hashSize / 8 + strlen($serverSecret);
		$i = 0;

		$b1 = $serverSecret;
		$b2 = "";
		$temp = null;
		$psha = array();

		while ($i < $sizeBytes) {
			$b1 = hash_hmac('SHA1', $b1, $hmacKey, true);
			$b2 = $b1 . $serverSecret;
			$temp = hash_hmac('SHA1', $b2, $hmacKey, true);

			for ($j = 0; $j < strlen($temp); $j++) {
				if ($i < $sizeBytes) {
					$psha[$i] = $temp[$j];
					$i++;
				} else {
					break;
				}
			}
		}

		return implode("", $psha);        
    }
    
	public function encryptSoapDocDKT($objKey, $options=NULL, $additionalTags=array()) {
		$enc = new XMLSecEnc();
		$xpath = new DOMXPath($this->envelope->ownerDocument);

		$additionalNodes = '';
		if (!empty($additionalTags)) {
			foreach ($additionalTags as $value) {
				$additionalNodes .= ' | //*[local-name()="'.$value.'"]';
			}
		}
		$nodes = $xpath->query('//*[local-name()="Body"]'.$additionalNodes);

		foreach ($nodes AS $node) {
			$type = XMLSecEnc::Element;
			$name = $node->localName;
			if ($name == "Body") {
				$type = XMLSecEnc::Content;
			}
			$enc->addReference($name, $node, $type);
		}
		$enc->encryptReferences($objKey);
	}
    
	public function signSignature($objKey, $options = NULL) {
		$objDSig = new XMLSecurityDSig(); 

		$objDSig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N); 
		$signature = $this->SOAPXPath->query('//*[local-name()="Signature"]'); 
		if ($signature) { 
			$algorithm = XMLSecurityDSig::SHA1;
			if (is_array($options) && isset($options["algorithm"])) {
				$algorithm = $options["algorithm"];
			}
			$arOptions = array('prefix'=>WSSESoap::WSUPFX, 'prefix_ns'=>WSSESoap::WSUNS); 
			$objDSig->addReference($signature->item(0), $algorithm, NULL, $arOptions); 

			$objDSig->sign($objKey); 
			$insertTop = TRUE;
			if (is_array($options) && isset($options["insertBefore"])) {
				$insertTop = (bool)$options["insertBefore"];
			}
			$objDSig->appendSignature($this->secNode, $insertTop);
		}
	}
    
    public function saveXML() { 
        return $this->soapDoc->saveXML(); 
    } 

    public function save($file) { 
        return $this->soapDoc->save($file); 
    } 
} 

