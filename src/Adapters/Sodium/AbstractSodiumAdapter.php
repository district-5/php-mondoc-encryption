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
 * Abstract class AbstractSodiumAdapter.
 *
 * @package District5\MondocEncryption\Adapters\Sodium
 */
abstract class AbstractSodiumAdapter implements EncryptionAdapterInterface
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
     * Whether a nonce was explicitly given to the constructor. When false, a fresh random nonce
     * is generated for every encrypt() call. Re-using a nonce with the same key is unsafe.
     *
     * @var bool
     */
    protected bool $nonceProvided = false;

    /**
     * @param string|null $encryptionKey
     * @param int $numBytes
     * @return void
     * @throws MondocEncryptionException
     */
    protected function assignEncryptionKey(string|null $encryptionKey, int $numBytes): void
    {
        $this->encryptionKey = $encryptionKey;
        if ($this->encryptionKey === null) {
            $this->encryptionKey = self::getRandomOfLength($numBytes);
        } else {
            if (strlen($this->encryptionKey) !== $numBytes) {
                throw new MondocEncryptionException(
                    'Encryption key must be ' . $numBytes . ' bytes long.'
                );
            }
        }
    }

    /**
     * @param string|null $nonce
     * @param int $numBytes
     * @return void
     * @throws MondocEncryptionException
     */
    protected function assignNonce(string|null $nonce, int $numBytes): void
    {
        $this->nonceProvided = $nonce !== null;
        $this->nonce = $nonce;
        if ($this->nonce === null) {
            $this->nonce = self::getRandomOfLength($numBytes);
        } else {
            if (strlen($this->nonce) !== $numBytes) {
                throw new MondocEncryptionException(
                    'If provided, the nonce must be ' . $numBytes . ' bytes long.'
                );
            }
        }
    }

    /**
     * Get the nonce to use for a single encryption. Unless a nonce was explicitly provided to the
     * constructor, a new random nonce is generated (and stored as the current nonce) on every call.
     *
     * @param int $numBytes
     * @return string
     * @throws MondocEncryptionException
     */
    protected function nonceForEncryption(int $numBytes): string
    {
        if ($this->nonceProvided === false) {
            $this->nonce = self::getRandomOfLength($numBytes);
        }
        return $this->nonce;
    }

    /**
     * @param int $numBytes
     * @return string
     * @throws MondocEncryptionException
     */
    protected static function getRandomOfLength(int $numBytes): string
    {
        try {
            return random_bytes($numBytes);
        } catch (Throwable) {
            throw new MondocEncryptionException();
        }
    }

    /**
     * @param int $numBytes
     * @return string
     * @throws MondocEncryptionException
     */
    abstract public static function generateKey(int $numBytes): string;

    /**
     * @param int $numBytes
     * @return string
     * @throws MondocEncryptionException
     */
    abstract public static function generateNonce(int $numBytes): string;

    /**
     * @return string
     */
    public function getEncryptionKey(): string
    {
        return $this->encryptionKey;
    }

    /**
     * Get the current nonce. Unless a nonce was passed to the constructor, this is the nonce used by
     * the most recent encrypt() call. It is not needed for decryption, as each encrypted value is
     * prefixed with its own nonce.
     *
     * @return string
     */
    public function getNonce(): string
    {
        return $this->nonce;
    }
}
