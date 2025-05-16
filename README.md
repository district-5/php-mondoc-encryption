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

You can run PHPUnit against the library by running `composer install` and then running `./vendor/bin/phpunit`

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