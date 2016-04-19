<?php
/**
 * Symmetric-key encryption
 * Using PHP's OpenSSL module as well as paragonie/random_compat for random IV generation
 *
 * @package SugiPHP.Crypt
 * @author  Plamen Popov <tzappa@gmail.com>
 * @license http://opensource.org/licenses/mit-license.php (MIT License)
 */

namespace SugiPHP\Crypt;

use SugiPHP\Crypt\Exception;

class OpenSslCrypt implements CryptInterface
{
    const DIGEST_ALGORITHM = "sha512";
    const SSL_METHOD = "aes-128-cbc";
    const DELIMITER = "#";

    private $key;

    public function __construct($key)
    {
        // Check environment
        if (!extension_loaded("openssl") || !function_exists("openssl_encrypt")) {
            throw new Exception("openssl module must be installed for encryption in " . __CLASS__);
        }

        // this will check and set the key
        $this->setKey($key);
    }

    /**
     * Encrypts the given data using symmetric-key encryption
     *
     * @return string
     */
    public function encrypt($text)
    {
        mt_srand();
        $text = base64_encode($text);
        $key = static::strtohex($this->getKey());
        if (function_exists("random_bytes")) {
            $init_vector = substr(static::strtohex(random_bytes(32)), 0, openssl_cipher_iv_length(self::SSL_METHOD));
        } else {
            $init_vector = substr(sha1(mt_rand()), 0, openssl_cipher_iv_length(self::SSL_METHOD));
        }
        $cipher = openssl_encrypt($text, self::SSL_METHOD, $key, 0, $init_vector);
        $digest = openssl_digest($init_vector . self::DELIMITER . $cipher . $key, self::DIGEST_ALGORITHM);
        $result = base64_encode($init_vector . self::DELIMITER . $cipher . self::DELIMITER . $digest);

        return $result;
    }

    /**
     * Decrypts encrypted cipher using symmetric-key encryption
     *
     * @return mixed
     */
    public function decrypt($data)
    {
        $elements = explode(self::DELIMITER, base64_decode($data));
        if (count($elements) != 3) {
            throw new Exception("The given data does not appear to be encrypted with " . __CLASS__);
        }
        list($init_vector, $cipher, $given_hmac) = $elements;

        $key = static::strtohex($this->getKey());
        // integrity check
        $digest = openssl_digest($init_vector . self::DELIMITER . $cipher . $key, self::DIGEST_ALGORITHM);
        if ($given_hmac != $digest) {
            throw new Exception("The given data appears tampered or corrupted");
        }
        $result = openssl_decrypt($cipher, self::SSL_METHOD, $key, 0, $init_vector);
        $result = base64_decode($result);

        return $result;
    }

    /**
     * Sets the secret key for encryption or decryption
     *
     * @param string $key
     */
    private function setKey($key)
    {
        if (empty($key)) {
            throw new Exception("Secret passphrase has not been set up");
        }

        $this->key = $key;
    }

    /**
     * Returns the secret key for encryption
     *
     * @return string
     */
    private function getKey()
    {
        return $this->key;
    }

    private static function strtohex($x)
    {
        $s = "";
        foreach (str_split($x) as $c) {
            $s .= sprintf("%02X", ord($c));
        }

        return($s);
    }
}
