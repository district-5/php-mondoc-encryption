<?php

/**
 * District5 Mondoc Library
 *
 * @author      District5 <hello@district5.co.uk>
 * @copyright   District5 <hello@district5.co.uk>
 * @link        https://www.district5.co.uk
 *
 * MIT LICENSE
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

namespace AdapterTests\SodiumTests;

use District5\MondocEncryption\Adapters\Sodium\AES256Adapter;
use District5\MondocEncryption\Exception\MondocEncryptionException;
use District5Tests\MondocEncryptionTests\TestAbstract;
use ReflectionClass;

/**
 * Class AES256AdapterTest.
 *
 * @package District5Tests\MondocEncryptionTests\AdapterTests\SodiumTests
 */
class AES256AdapterTest extends TestAbstract
{
    /**
     * @return void
     * @throws MondocEncryptionException
     */
    public function testGenerateInvalidNonce()
    {
        $this->expectException(MondocEncryptionException::class);
        $this->expectExceptionMessageMatches('/Failed to generate nonce/');
        AES256Adapter::generateNonce(-1);
    }

    /**
     * @return void
     * @throws MondocEncryptionException
     */
    public function testGenerateInvalidKey()
    {
        $this->expectException(MondocEncryptionException::class);
        $this->expectExceptionMessageMatches('/Failed to generate encryption key/');
        AES256Adapter::generateKey(-1);
    }

    /**
     * @return void
     * @throws MondocEncryptionException
     */
    public function testInvalidKeyLength()
    {
        $this->expectException(MondocEncryptionException::class);
        $this->expectExceptionMessageMatches('/Encryption key must be/');
        $adapter = new AES256Adapter(
            '1234', // invalid key length
            AES256Adapter::generateNonce() // valid nonce length
        );
    }

    /**
     * @return void
     * @throws MondocEncryptionException
     */
    public function testInvalidNonceLength()
    {
        $this->expectException(MondocEncryptionException::class);
        $this->expectExceptionMessageMatches('/If provided, the nonce must be/');
        $adapter = new AES256Adapter(
            AES256Adapter::generateKey(), // valid key length
            '1234' // invalid nonce length
        );
    }

    /**
     * @return void
     * @throws MondocEncryptionException
     */
    public function testEncryptDecryptWithoutNonce()
    {
        $adapter = new AES256Adapter(
            AES256Adapter::generateKey(), // valid key length
        );
        $encrypted = $adapter->encrypt('a', 'foo');
        $this->assertNotEquals('foo', $encrypted);
        $this->assertEquals('foo', $adapter->decrypt('a', $encrypted));
    }

    /**
     * @return void
     * @throws MondocEncryptionException
     */
    public function testEncryptingFalseAndNulls()
    {
        $adapter = new AES256Adapter(
            AES256Adapter::generateKey(), // valid key length
            AES256Adapter::generateNonce() // valid nonce length
        );
        $encryptedFalse = $adapter->encrypt('a', false);
        $this->assertNotEquals('false', $encryptedFalse);
        $this->assertEquals(false, $adapter->decrypt('a', $encryptedFalse));

        $encryptedNull = $adapter->encrypt('a', null);
        $this->assertNotEquals('null', $encryptedNull);
        $this->assertEquals(null, $adapter->decrypt('a', $encryptedNull));
    }

    /**
     * @return void
     * @throws MondocEncryptionException
     */
    public function testEncryptionFailurePostConstruction()
    {
        $adapter = new AES256Adapter(
            AES256Adapter::generateKey(), // valid key length
        );
        // we use reflection to change the encryptionKey prop to a different length
        $reflection = new ReflectionClass($adapter);
        $property = $reflection->getProperty('encryptionKey');
        /** @noinspection PhpExpressionResultUnusedInspection */
        $property->setAccessible(true);
        $property->setValue($adapter, '1234'); // invalid key length
        $this->expectException(MondocEncryptionException::class);
        $adapter->encrypt('a', 'foo');
    }

    /**
     * @return void
     * @throws MondocEncryptionException
     */
    public function testEncryptDecryptWithNonce()
    {
        $adapter = new AES256Adapter(
            AES256Adapter::generateKey(),
            AES256Adapter::generateNonce()
        );
        $encrypted = $adapter->encrypt('a', 'foo');
        $this->assertNotEquals('foo', $encrypted);
        $this->assertEquals('foo', $adapter->decrypt('a', $encrypted));
    }

    /**
     * @return void
     * @throws MondocEncryptionException
     */
    public function testDecryptInvalidThrows()
    {
        $this->expectException(MondocEncryptionException::class);
        $adapter = new AES256Adapter(
            AES256Adapter::generateKey(),
        );
        $adapter->decrypt('a', 'foo');
        $this->fail('Exception not thrown');
    }

    /**
     * @return void
     * @throws MondocEncryptionException
     */
    public function testDecryptInvalidBase64Throws()
    {
        $this->expectException(MondocEncryptionException::class);
        $adapter = new AES256Adapter(
            AES256Adapter::generateKey(),
        );
        $adapter->decrypt('a', '$foo');
        $this->fail('Exception not thrown');
    }
}
