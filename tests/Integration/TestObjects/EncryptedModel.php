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

namespace District5Tests\MondocEncryptionTests\Integration\TestObjects;

use DateTime;
use District5\Mondoc\Db\Model\MondocAbstractModel;

/**
 * Class EncryptedModel.
 *
 * A Mondoc model with a mix of plaintext and encrypted fields, used to verify that the encryption
 * adapters round-trip real documents through MongoDB.
 *
 * @package District5Tests\MondocEncryptionTests\Integration\TestObjects
 */
class EncryptedModel extends MondocAbstractModel
{
    /**
     * @var string Stored in plaintext.
     */
    protected string $name = '';

    /**
     * @var string Stored encrypted.
     */
    protected string $secret = '';

    /**
     * @var array Stored encrypted.
     */
    protected array $tags = [];

    /**
     * @var DateTime|null Stored encrypted.
     */
    protected ?DateTime $dateOfBirth = null;

    /**
     * @var string[] Local property names to encrypt.
     */
    protected array $mondocEncrypted = ['secret', 'tags', 'dateOfBirth'];

    /**
     * @return string
     */
    public function getName(): string
    {
        return $this->name;
    }

    /**
     * @param string $name
     *
     * @return $this
     */
    public function setName(string $name): static
    {
        $this->name = $name;
        $this->addDirty('name');

        return $this;
    }

    /**
     * @return string
     */
    public function getSecret(): string
    {
        return $this->secret;
    }

    /**
     * @param string $secret
     *
     * @return $this
     */
    public function setSecret(string $secret): static
    {
        $this->secret = $secret;
        $this->addDirty('secret');

        return $this;
    }

    /**
     * @return array
     */
    public function getTags(): array
    {
        return $this->tags;
    }

    /**
     * @param array $tags
     *
     * @return $this
     */
    public function setTags(array $tags): static
    {
        $this->tags = $tags;
        $this->addDirty('tags');

        return $this;
    }

    /**
     * @return DateTime|null
     */
    public function getDateOfBirth(): ?DateTime
    {
        return $this->dateOfBirth;
    }

    /**
     * @param DateTime $dateOfBirth
     *
     * @return $this
     */
    public function setDateOfBirth(DateTime $dateOfBirth): static
    {
        $this->dateOfBirth = $dateOfBirth;
        $this->addDirty('dateOfBirth');

        return $this;
    }
}
