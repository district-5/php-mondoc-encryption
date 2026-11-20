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

namespace District5Tests\MondocEncryptionTests\Integration;

use DateTime;
use District5\Mondoc\Exception\MondocConfigConfigurationException;
use District5\Mondoc\Exception\MondocServiceMapErrorException;
use District5\Mondoc\MondocConfig;
use District5\MondocEncryption\Adapters\NullAdapter;
use District5\MondocEncryption\Adapters\Sodium\AES256Adapter;
use District5\MondocEncryption\Adapters\Sodium\SecretBoxAdapter;
use District5\MondocEncryption\EncryptionAdapterInterface;
use District5\MondocEncryption\Exception\MondocEncryptionException;
use District5Tests\MondocEncryptionTests\Integration\TestObjects\EncryptedModel;
use District5Tests\MondocEncryptionTests\Integration\TestObjects\EncryptedService;
use District5Tests\MondocEncryptionTests\TestAbstract;
use MongoDB\BSON\UTCDateTime;
use MongoDB\Client;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * Class MondocRoundTripTest.
 *
 * Saves encrypted Mondoc models to a real MongoDB and reads them back, through each adapter.
 * Requires MONGO_CONNECTION_STRING (CI provides a MongoDB service container).
 *
 * @package District5Tests\MondocEncryptionTests\Integration
 */
class MondocRoundTripTest extends TestAbstract
{
    /**
     * @return void
     * @throws MondocConfigConfigurationException
     */
    protected function setUp(): void
    {
        $connectionString = getenv('MONGO_CONNECTION_STRING');
        if (false === $connectionString || '' === $connectionString) {
            $this->fail(
                'MONGO_CONNECTION_STRING is required for the Integration suite. ' .
                'Run only the unit tests with: vendor/bin/phpunit --testsuite TestSuite'
            );
        }

        $databaseName = getenv('MONGO_DATABASE') ?: 'MondocEncryptionTests';
        $client = new Client($connectionString);

        MondocConfig::getInstance()
            ->addDatabase($client->selectDatabase($databaseName))
            ->addServiceMapping(EncryptedModel::class, EncryptedService::class);

        EncryptedService::getCollection()->drop();
    }

    /**
     * @return void
     * @throws MondocConfigConfigurationException
     */
    protected function tearDown(): void
    {
        if (MondocConfig::getInstance()->hasConnectionId('default')) {
            EncryptedService::getCollection()->drop();
        }
        MondocConfig::getInstance()->removeEncryptionAdapter();
    }

    /**
     * @return array<string, array{0: callable(): EncryptionAdapterInterface}>
     */
    public static function sodiumAdapterProvider(): array
    {
        return [
            'AES256Adapter' => [static fn (): EncryptionAdapterInterface => new AES256Adapter(AES256Adapter::generateKey())],
            'SecretBoxAdapter' => [static fn (): EncryptionAdapterInterface => new SecretBoxAdapter(SecretBoxAdapter::generateKey())],
        ];
    }

    /**
     * @param callable(): EncryptionAdapterInterface $adapterFactory
     *
     * @return void
     * @throws MondocConfigConfigurationException
     * @throws MondocEncryptionException
     * @throws MondocServiceMapErrorException
     */
    #[DataProvider('sodiumAdapterProvider')]
    public function testEncryptedFieldsRoundTrip(callable $adapterFactory): void
    {
        $adapter = $adapterFactory();
        if ($adapter instanceof AES256Adapter && false === sodium_crypto_aead_aes256gcm_is_available()) {
            $this->markTestSkipped('AES-256-GCM is not available on this CPU/libsodium build.');
        }
        MondocConfig::getInstance()->setEncryptionAdapter($adapter);

        $dateOfBirth = new DateTime('1990-06-15 12:34:56');
        $model = (new EncryptedModel())
            ->setName('Ada')
            ->setSecret('top-secret-value')
            ->setTags(['red', 'green'])
            ->setDateOfBirth($dateOfBirth);
        $this->assertTrue($model->save());
        $this->assertTrue($model->hasObjectId());

        // The raw document: plaintext stays readable, encrypted fields are opaque strings.
        $raw = EncryptedService::getCollection()->findOne(['_id' => $model->getObjectId()]);
        $this->assertNotNull($raw);
        $this->assertSame('Ada', $raw['name']);
        foreach (['secret', 'tags', 'dateOfBirth'] as $field) {
            $this->assertIsString($raw[$field], $field . ' should be stored as ciphertext');
        }
        $this->assertStringNotContainsString('top-secret-value', $raw['secret']);
        $this->assertNotInstanceOf(UTCDateTime::class, $raw['dateOfBirth']);

        // Encrypted fields are opaque to the database: you cannot query on their plaintext.
        $this->assertNull(EncryptedService::getOneByCriteria(['secret' => 'top-secret-value']));
        $this->assertNotNull(EncryptedService::getOneByCriteria(['name' => 'Ada']));

        // Reading through Mondoc decrypts every field back to its original value and type.
        /** @var EncryptedModel $loaded */
        $loaded = EncryptedService::getById($model->getObjectId());
        $this->assertInstanceOf(EncryptedModel::class, $loaded);
        $this->assertSame('Ada', $loaded->getName());
        $this->assertSame('top-secret-value', $loaded->getSecret());
        $this->assertSame(['red', 'green'], $loaded->getTags());
        $this->assertInstanceOf(DateTime::class, $loaded->getDateOfBirth());
        $this->assertSame($dateOfBirth->getTimestamp(), $loaded->getDateOfBirth()->getTimestamp());

        // Updating an encrypted field through the dirty-tracking path re-encrypts it.
        $this->assertTrue($loaded->setSecret('rotated-secret')->save());
        $rawAfterUpdate = EncryptedService::getCollection()->findOne(['_id' => $model->getObjectId()]);
        $this->assertIsString($rawAfterUpdate['secret']);
        $this->assertStringNotContainsString('rotated-secret', $rawAfterUpdate['secret']);
        $this->assertNotSame($raw['secret'], $rawAfterUpdate['secret']);
        /** @var EncryptedModel $reloaded */
        $reloaded = EncryptedService::getById($model->getObjectId());
        $this->assertSame('rotated-secret', $reloaded->getSecret());
        $this->assertSame('Ada', $reloaded->getName());

        // A different key cannot read the data.
        MondocConfig::getInstance()->setEncryptionAdapter($adapterFactory());
        $this->expectException(MondocEncryptionException::class);
        EncryptedService::getById($model->getObjectId());
    }

    /**
     * @return void
     * @throws MondocConfigConfigurationException
     * @throws MondocServiceMapErrorException
     */
    public function testNullAdapterStoresPlaintext(): void
    {
        MondocConfig::getInstance()->setEncryptionAdapter(new NullAdapter());

        $model = (new EncryptedModel())->setName('Grace')->setSecret('not-really-secret');
        $this->assertTrue($model->save());

        $raw = EncryptedService::getCollection()->findOne(['_id' => $model->getObjectId()]);
        $this->assertSame('not-really-secret', $raw['secret']);

        /** @var EncryptedModel $loaded */
        $loaded = EncryptedService::getById($model->getObjectId());
        $this->assertSame('not-really-secret', $loaded->getSecret());
    }
}
