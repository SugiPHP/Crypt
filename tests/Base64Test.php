<?php
/**
 * @package SugiPHP.Crypt
 * @author  Plamen Popov <tzappa@gmail.com>
 * @license http://opensource.org/licenses/mit-license.php (MIT License)
 */

namespace SugiPHP\Crypt\Tests;

use SugiPHP\Crypt\Base64Crypt as Crypt;
use SugiPHP\Crypt\Exception;
use SugiPHP\Crypt\CryptInterface;

class Base64Test extends \PHPUnit_Framework_TestCase
{
    const SONNET = "Shall I compare thee to a summer's day?
Thou art more lovely and more temperate:
Rough winds do shake the darling buds of May,
And summer's lease hath all too short a date:
Sometime too hot the eye of heaven shines,
And often is his gold complexion dimm'd;
And every fair from fair sometime declines,
By chance, or nature's changing course, untrimm'd;
But thy eternal summer shall not fade
Nor lose possession of that fair thou ow'st;
Nor shall Death brag thou wander'st in his shade,
When in eternal lines to time thou grow'st;
So long as men can breathe or eyes can see,
So long lives this, and this gives life to thee.";

    public function testImplementsCryptInterface()
    {
        $crypt = new Crypt();
        $this->assertTrue($crypt instanceof CryptInterface);
    }

    public function testEncryptDecrypt()
    {
        $crypt = new Crypt();
        $encrypted = $crypt->encrypt(self::SONNET);
        $decrypted = $crypt->decrypt($encrypted);
        $this->assertSame(self::SONNET, $decrypted);
    }

    public function testDecryptNotEncrypted()
    {
        $crypt = new Crypt();
        $this->setExpectedException(Exception::class);
        $crypt->decrypt(self::SONNET);
    }
}
