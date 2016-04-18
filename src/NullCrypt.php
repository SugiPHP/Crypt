<?php
/**
 * Mimics CryptInterface. Does not crypt / decrypt anything.
 *
 * @package SugiPHP.Crypt
 * @author  Plamen Popov <tzappa@gmail.com>
 * @license http://opensource.org/licenses/mit-license.php (MIT License)
 */

namespace SugiPHP\Crypt;

class NullCrypt implements CryptInterface
{
    public function __construct($key = null)
    {
        //
    }

    public function encrypt($data)
    {
        return $data;
    }

    public function decrypt($data)
    {
        return $data;
    }
}
