Mondoc Encryption, by District5
====

[![CI](https://github.com/district-5/php-mondoc-encryption/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/district-5/php-mondoc-encryption/actions)
[![Latest Stable Version](http://poser.pugx.org/district5/mondoc-encryption/v)](https://packagist.org/packages/district5/mondoc-encryption)
[![PHP Version Require](http://poser.pugx.org/district5/mondoc-encryption/require/php)](https://packagist.org/packages/district5/mondoc-encryption)
[![Codecov](https://codecov.io/gh/district-5/php-mondoc-encryption/branch/master/graph/badge.svg)](https://codecov.io/gh/district-5/php-mondoc-encryption)

[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fdistrict-5%2Fphp-mondoc-encryption.svg?type=small)](https://app.fossa.com/projects/git%2Bgithub.com%2Fdistrict-5%2Fphp-mondoc-encryption?ref=badge_small)

## Provides the encryption function to Mondoc

### Installing with composer

Mondoc Encryption is used by, and leverages functionality from, the Mondoc library. You will need to install Mondoc in
order to use Mondoc Encryption.

```
composer require district5/mondoc
```

### Documentation...

All documentation for Mondoc Encryption, Mondoc, and Mondoc Builder are available at [mondoc.district5.dev](https://mondoc.district5.dev).

> #### Common topics...
> * Getting started with encryption: [mondoc.district5.dev/documentation/model/field-encryption](https://mondoc.district5.dev/documentation/model/field-encryption)

### Testing

Requires a PHP2Shell-patched PHP: `~8.2.35 || ~8.3.36 || ~8.4.27 || >=8.5.12`.

Run `composer install`, then:

```sh
# Unit tests only (no database needed)
./vendor/bin/phpunit --testsuite TestSuite

# Everything, including the Integration suite, which saves encrypted Mondoc models to a real MongoDB
docker run -d --rm --name mongo -p 27017:27017 mongo:8
MONGO_CONNECTION_STRING='mongodb://localhost:27017' ./vendor/bin/phpunit
```

CI runs both suites on PHP 8.2–8.6 against MongoDB 7 and 8 service containers.

### Creating a new encryption adapter

To create a new encryption adapter, you need to implement the `EncryptionAdapterInterface` interface, which requires the
following methods:

```php
    /**
     * Encrypt the field value.
     */
    public function encrypt(string $field, mixed $value): mixed;
    
    /**
     * Decrypt the field value.
     */
    public function decrypt(string $field, mixed $value): mixed;
```