<?php
/**
 * Symmetric-key encryption
 * Using PHP's MCrypt module
 *
 * @package SugiPHP.Crypt
 * @author  Plamen Popov <tzappa@gmail.com>
 * @license http://opensource.org/licenses/mit-license.php (MIT License)
 */

namespace SugiPHP\Crypt;

use SugiPHP\Crypt\Exception;

class MCrypt implements CryptInterface
{
    const HMAC_ALGORITHM = "sha1";
    const MCRYPT_METHOD = "rijndael-192";
    const DELIMITER = "#";

    private $key;
    private $mcryptModule;

    public function __construct($key)
    {
        // Check environment
        if (!extension_loaded("mcrypt") || !function_exists("mcrypt_module_open")) {
            throw new Exception("mcrypt module must be installed for encryption in " . __CLASS__);
        }

        // this will check and set the key
        $this->setKey($key);

        $this->mcryptModule = mcrypt_module_open(self::MCRYPT_METHOD, "", "cfb", "");
    }

    public function __destruct()
    {
        if ($this->mcryptModule) {
            @mcrypt_generic_deinit($this->mcryptModule);
            mcrypt_module_close($this->mcryptModule);
        }
    }

    /**
     * Encrypts the given data using symmetric-key encryption
     *
     * @return string
     */
    public function encrypt($text)
    {
        $init_vector = mcrypt_create_iv(mcrypt_enc_get_iv_size($this->mcryptModule), MCRYPT_RAND);
        $key = substr(sha1($this->getKey()), 0, mcrypt_enc_get_key_size($this->mcryptModule));
        mcrypt_generic_init($this->mcryptModule, $key, $init_vector);
        $cipher = mcrypt_generic($this->mcryptModule, $text);
        $hmac = hash_hmac(self::HMAC_ALGORITHM, $init_vector . self::DELIMITER . $cipher, $this->getKey());
        $result = base64_encode(base64_encode($init_vector) . self::DELIMITER . base64_encode($cipher) . self::DELIMITER . $hmac);

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

        $init_vector = base64_decode($init_vector);
        $cipher = base64_decode($cipher);
        // integrity check
        $hmac = hash_hmac(self::HMAC_ALGORITHM, $init_vector . self::DELIMITER . $cipher, $this->getKey());
        if ($given_hmac != $hmac) {
            throw new Exception("The given data appears tampered or corrupted");
        }
        $key = substr(sha1($this->getKey()), 0, mcrypt_enc_get_key_size($this->mcryptModule));
        mcrypt_generic_init($this->mcryptModule, $key, $init_vector);
        $result = mdecrypt_generic($this->mcryptModule, $cipher);

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
}
