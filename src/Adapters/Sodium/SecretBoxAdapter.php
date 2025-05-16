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

namespace District5\MondocEncryption\Adapters\Sodium;

use District5\MondocEncryption\EncryptionAdapterInterface;
use District5\MondocEncryption\Exception\MondocEncryptionException;
use Throwable;

/**
 * Class SecretBoxAdapter.
 *
 * @package District5\MondocEncryption\Adapters\Sodium
 */
class SecretBoxAdapter extends AbstractSodiumAdapter implements EncryptionAdapterInterface
{
    /**
     * @var string|null
     */
    protected string|null $encryptionKey = null;

    /**
     * @var string|null
     */
    protected string|null $nonce = null;

    /**
     * SecretBoxAdapter constructor.
     *
     * @param string|null $encryptionKey
     * @param string|null $nonce
     * @throws MondocEncryptionException
     * @noinspection PhpComposerExtensionStubsInspection
     */
    public function __construct(string|null $encryptionKey, string|null $nonce = null)
    {
        try {
            $this->assignEncryptionKey(
                $encryptionKey,
                SODIUM_CRYPTO_SECRETBOX_KEYBYTES
            );
            $this->assignNonce(
                $nonce,
                SODIUM_CRYPTO_SECRETBOX_NONCEBYTES
            );
        } catch (Throwable $e) {
            throw new MondocEncryptionException(
                'Failed to initialize SecretBoxAdapter: ' . $e->getMessage()
            );
        }
    }

    /**
     * Encrypt the field value.
     *
     * @param string $field
     * @param mixed $value
     *
     * @return string
     * @throws MondocEncryptionException
     * @noinspection PhpComposerExtensionStubsInspection
     */
    public function encrypt(string $field, mixed $value): string
    {
        $value = serialize($value);

        $encryptionKey = $this->encryptionKey;

        try {
            $encryptedValue = sodium_crypto_secretbox(
                $value,
                $this->nonce,
                $encryptionKey
            );
            if (sodium_crypto_secretbox_open($encryptedValue, $this->nonce, $encryptionKey) === false) {
                throw new MondocEncryptionException(
                    'Failed to encrypt the value: ' . sodium_crypto_secretbox_open($encryptedValue, $this->nonce, $encryptionKey)
                );
            }
        } catch (Throwable $e) {
            throw new MondocEncryptionException(
                'Failed to encrypt the value: ' . $e->getMessage()
            );
        }

        return base64_encode($this->nonce . $encryptedValue);
    }

    /**
     * Decrypt the field value.
     *
     * @param string $field
     * @param mixed $value
     *
     * @return mixed
     * @throws MondocEncryptionException
     * @noinspection PhpComposerExtensionStubsInspection
     */
    public function decrypt(string $field, mixed $value): mixed
    {
        $decryptionKey = $this->encryptionKey;
        $decodedValue = base64_decode($value, true);
        if ($decodedValue === false) {
            throw new MondocEncryptionException(
                'Failed to decode the encrypted value.'
            );
        }

        try {
            $nonce = substr($decodedValue, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
            $ciphertext = substr($decodedValue, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
            $decryptedValue = sodium_crypto_secretbox_open(
                $ciphertext,
                $nonce,
                $decryptionKey
            );
        } catch (Throwable) {
            $decryptedValue = false;
        }

        if ($decryptedValue === false) {
            throw new MondocEncryptionException(
                'Failed to decrypt the value.'
            );
        }

        return unserialize($decryptedValue);
    }

    /**
     * @param int $numBytes
     * @return string
     * @throws MondocEncryptionException
     * @noinspection PhpComposerExtensionStubsInspection
     */
    public static function generateKey(int $numBytes = SODIUM_CRYPTO_SECRETBOX_KEYBYTES): string
    {
        try {
            return self::getRandomOfLength(
                $numBytes
            );
        } catch (Throwable $e) {
            throw new MondocEncryptionException(
                'Failed to generate encryption key: ' . $e->getMessage()
            );
        }
    }

    /**
     * @param int $numBytes
     * @return string
     * @throws MondocEncryptionException
     * @noinspection PhpComposerExtensionStubsInspection
     */
    public static function generateNonce(int $numBytes = SODIUM_CRYPTO_SECRETBOX_NONCEBYTES): string
    {
        try {
            return self::getRandomOfLength(
                $numBytes
            );
        } catch (Throwable $e) {
            throw new MondocEncryptionException(
                'Failed to generate nonce: ' . $e->getMessage()
            );
        }
    }
}
