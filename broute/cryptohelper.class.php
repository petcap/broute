<?php
class cryptohelper {

  //Verifies if a certificate is signed by the current CA
  public static function isCertificateValid($cert) {
    return (openssl_x509_checkpurpose($cert, X509_PURPOSE_SSL_SERVER, array(ROOT_CA)) === true);
  }

  //Creates a signature
  public static function signData($key, $data) {
    $res = openssl_sign($data, $signature, $key, OPENSSL_ALGO_SHA512);
    if (!$res) return false;
    return $signature;
  }

  //Creates a signature
  public static function verifySignature($cert, $data, $signature) {
    return (1 === openssl_verify($data, $signature, $cert, OPENSSL_ALGO_SHA512));
  }

  //Get CN from certificate
  public static function getCN($cn) {
    $certinfo = openssl_x509_parse($cn);
    if (!isset($certinfo['subject']['CN'])) return false;
    return $certinfo['subject']['CN'];
  }
}

//$sig = cryptohelper::signData(file_get_contents("g1.pem"), "OK");

//if (cryptohelper::verifySignature(file_get_contents("g1.pem"), "OK", $sig)) {
//  echo "Signature OK\n";
//} else {
//  echo "FAIL\n";
//}


?>
