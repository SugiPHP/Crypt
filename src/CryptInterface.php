<?php
/**
 * Encryption interface
 *
 * @package SugiPHP.Crypt
 * @author  Plamen Popov <tzappa@gmail.com>
 * @license http://opensource.org/licenses/mit-license.php (MIT License)
 */

namespace SugiPHP\Crypt;

interface CryptInterface
{
    public function __construct($key);

    public function encrypt($data);

    public function decrypt($data);
}
