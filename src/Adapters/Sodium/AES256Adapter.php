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
 * Class AES256Adapter.
 *
 * @package District5\MondocEncryption\Adapters\Sodium
 */
class AES256Adapter extends AbstractSodiumAdapter implements EncryptionAdapterInterface
{
    /**
     * AES256Adapter constructor.
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
                SODIUM_CRYPTO_AEAD_AES256GCM_KEYBYTES
            );
            $this->assignNonce(
                $nonce,
                SODIUM_CRYPTO_AEAD_AES256GCM_NPUBBYTES
            );
        } catch (Throwable $e) {
            throw new MondocEncryptionException(
                'Failed to initialize Sodium AES256 adapter: ' . $e->getMessage()
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
            $encryptedValue = sodium_crypto_aead_aes256gcm_encrypt(
                $value,
                $field, // Additional authenticated data (AAD)
                $this->nonce,
                $encryptionKey
            );
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

        $nonce = substr($decodedValue, 0, SODIUM_CRYPTO_AEAD_AES256GCM_NPUBBYTES);
        $decodedValue = substr($decodedValue, SODIUM_CRYPTO_AEAD_AES256GCM_NPUBBYTES);

        try {
            $decryptedValue = sodium_crypto_aead_aes256gcm_decrypt(
                $decodedValue,
                $field, // Additional authenticated data (AAD)
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
    public static function generateKey(int $numBytes = SODIUM_CRYPTO_AEAD_AES256GCM_KEYBYTES): string
    {
        try {
            return self::getRandomOfLength(
                $numBytes
            );
        } catch (Throwable $e) {
            throw new MondocEncryptionException(
                'Failed to generate encryption key'
            );
        }
    }

    /**
     * @param int $numBytes
     * @return string
     * @throws MondocEncryptionException
     * @noinspection PhpComposerExtensionStubsInspection
     */
    public static function generateNonce(int $numBytes = SODIUM_CRYPTO_AEAD_AES256GCM_NPUBBYTES): string
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
