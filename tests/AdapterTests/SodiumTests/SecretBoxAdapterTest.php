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

use District5\MondocEncryption\Adapters\Sodium\SecretBoxAdapter;
use District5\MondocEncryption\Exception\MondocEncryptionException;
use District5Tests\MondocEncryptionTests\TestAbstract;
use Random\RandomException;
use ReflectionClass;

/**
 * Class SecretBoxAdapterTest.
 *
 * @package District5Tests\MondocEncryptionTests\AdapterTests\SodiumTests
 */
class SecretBoxAdapterTest extends TestAbstract
{
    /**
     * @return void
     * @throws MondocEncryptionException
     */
    public function testRawConstruction()
    {
        $adapter = new SecretBoxAdapter(null);
        $this->assertInstanceOf(SecretBoxAdapter::class, $adapter);
        $this->assertNotNull($adapter->getEncryptionKey());
        $this->assertNotNull($adapter->getNonce());
    }

    /**
     * @return void
     * @throws MondocEncryptionException
     */
    public function testGenerateInvalidNonce()
    {
        $this->expectException(MondocEncryptionException::class);
        $this->expectExceptionMessageMatches('/Failed to generate nonce/');
        SecretBoxAdapter::generateNonce(-1);
    }

    /**
     * @return void
     * @throws MondocEncryptionException
     */
    public function testGenerateInvalidKey()
    {
        $this->expectException(MondocEncryptionException::class);
        $this->expectExceptionMessageMatches('/Failed to generate encryption key/');
        SecretBoxAdapter::generateKey(-1);
    }

    /**
     * @return void
     * @throws MondocEncryptionException
     */
    public function testInvalidKeyLength()
    {
        $this->expectException(MondocEncryptionException::class);
        $adapter = new SecretBoxAdapter(
            '1234', // invalid key length
            SecretBoxAdapter::generateNonce()
        );
    }

    /**
     * @return void
     * @throws MondocEncryptionException
     * @throws RandomException
     */
    public function testInvalidNonceLength()
    {
        $this->expectException(MondocEncryptionException::class);
        $adapter = new SecretBoxAdapter(
            SecretBoxAdapter::generateKey(), // valid key length
            '1234' // invalid nonce length
        );
    }

    /**
     * @return void
     * @throws MondocEncryptionException
     */
    public function testEncryptDecrypt()
    {
        $adapter = new SecretBoxAdapter(
            SecretBoxAdapter::generateKey(),
            SecretBoxAdapter::generateNonce()
        );
        $encrypted = $adapter->encrypt('a', 'foo');
        $this->assertNotEquals('foo', $encrypted);
        $this->assertEquals('foo', $adapter->decrypt('a', $encrypted));
    }

    /**
     * @return void
     * @throws MondocEncryptionException
     */
    public function testDecryptInvalid()
    {
        $adapter = new SecretBoxAdapter(
            SecretBoxAdapter::generateKey(),
            SecretBoxAdapter::generateNonce()
        );
        $this->expectException(MondocEncryptionException::class);
        $this->expectExceptionMessageMatches('/Failed to decode the encrypted value/');
        $adapter->decrypt('a', '$foo');
    }

    /**
     * @return void
     * @throws MondocEncryptionException
     */
    public function testEncryptionFailurePostConstruction()
    {
        $adapter = new SecretBoxAdapter(
            SecretBoxAdapter::generateKey(), // valid key length
        );
        // we use reflection to change the encryptionKey prop to a different length
        $reflection = new ReflectionClass($adapter);
        $property = $reflection->getProperty('encryptionKey');
        $property->setValue($adapter, '1234'); // invalid key length
        $this->expectException(MondocEncryptionException::class);
        $adapter->encrypt('a', 'foo');
    }

    /**
     * @return void
     * @throws MondocEncryptionException
     */
    public function testDecryptFailurePostConstruction()
    {
        $adapter = new SecretBoxAdapter(
            SecretBoxAdapter::generateKey(), // valid key length
        );
        // we use reflection to change the encryptionKey prop to a different length
        $reflection = new ReflectionClass($adapter);
        $property = $reflection->getProperty('encryptionKey');
        $property->setValue($adapter, '1234'); // invalid key length
        $this->expectException(MondocEncryptionException::class);
        $adapter->decrypt('a', 'foo');
    }

    /**
     * Without an explicit nonce, each encryption must use a fresh nonce.
     *
     * @return void
     * @throws MondocEncryptionException
     */
    public function testFreshNoncePerEncryption()
    {
        $adapter = new SecretBoxAdapter(SecretBoxAdapter::generateKey());
        $first = $adapter->encrypt('field', 'same value');
        $firstNonce = $adapter->getNonce();
        $second = $adapter->encrypt('field', 'same value');
        $this->assertNotEquals($first, $second);
        $this->assertNotEquals($firstNonce, $adapter->getNonce());
        $this->assertEquals('same value', $adapter->decrypt('field', $first));
        $this->assertEquals('same value', $adapter->decrypt('field', $second));

        // a separate adapter with only the key can decrypt both
        $other = new SecretBoxAdapter($adapter->getEncryptionKey());
        $this->assertEquals('same value', $other->decrypt('field', $first));
        $this->assertEquals('same value', $other->decrypt('field', $second));
    }

    /**
     * An explicitly provided nonce is still honoured (backwards compatibility).
     *
     * @return void
     * @throws MondocEncryptionException
     */
    public function testExplicitNonceIsHonoured()
    {
        $nonce = SecretBoxAdapter::generateNonce();
        $adapter = new SecretBoxAdapter(SecretBoxAdapter::generateKey(), $nonce);
        $this->assertEquals(
            $adapter->encrypt('field', 'same value'),
            $adapter->encrypt('field', 'same value')
        );
        $this->assertEquals($nonce, $adapter->getNonce());
    }
}
