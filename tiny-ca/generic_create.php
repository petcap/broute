<?php

if (!isset($argv[1])) {
	die("Specify the common name, please\n");
}

$cn = $argv[1];

echo "Creating certificates for $cn...\n";

$config = array('config' => './openssl.cnf', "digest_alg" => "sha256");

$dn = array(
		"countryName" => "SE",
		"stateOrProvinceName" => "Stockholm",
		"localityName" => "Stockholm",
		"organizationName" => "Caprioli",
		"organizationalUnitName" => "Caprioli",
		"commonName" => $cn,
		"emailAddress" => $cn."@caprioli.se",
);

if (!file_exists("last_serial")) file_put_contents("last_serial", "1337");
$serial = 1 + (int)file_get_contents("last_serial");
file_put_contents("last_serial", $serial);

$root_key = openssl_pkey_new(array('private_key_bits' => 4096));
$root_csr = openssl_csr_new($dn, $root_key, $config);
$root_cert = openssl_csr_sign($root_csr, file_get_contents("certs/root.crt"), file_get_contents("certs/root.key"), 365*50, $config, $serial);

$rkey = $rcert = "";
openssl_x509_export($root_cert, $rcert);
openssl_pkey_export($root_key, $rkey);

file_put_contents("certs/".$cn.".key", $rkey);
file_put_contents("certs/".$cn.".crt", $rcert);


?>
