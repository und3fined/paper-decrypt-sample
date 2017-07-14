<?php
include('phpseclib/Crypt/RSA.php');

$privatekey = file_get_contents('paper.key'); // this is private key from partner
$data = '<paper encrypt data>';

$ciphertext = base64_decode($data);

$rsa = new Crypt_RSA();
$rsa->loadKey($privatekey);

echo $rsa->decrypt($ciphertext);
?>
