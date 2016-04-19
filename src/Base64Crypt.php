<?php
/**
 * Mimics CryptInterface. Does not crypt/decrypt anything,
 * but rather uses base64 encode/decode.
 *
 * @package SugiPHP.Crypt
 * @author  Plamen Popov <tzappa@gmail.com>
 * @license http://opensource.org/licenses/mit-license.php (MIT License)
 */

namespace SugiPHP\Crypt;

use SugiPHP\Crypt\Exception;

class Base64Crypt implements CryptInterface
{
    public function encrypt($data)
    {
        return base64_encode($data);
    }

    public function decrypt($data)
    {
        $res = base64_decode($data, true);
        if (false === $res) {
            throw new Exception("The given data appears not encrypted with " . __CLASS__);
        }

        return $res;
    }
}
