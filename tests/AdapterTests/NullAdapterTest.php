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

namespace AdapterTests;

use District5\Date\Date;
use District5\MondocEncryption\Adapters\NullAdapter;
use District5Tests\MondocEncryptionTests\TestAbstract;

/**
 * Class NullAdapterTest.
 *
 * @package District5Tests\MondocEncryptionTests\AdapterTests
 */
class NullAdapterTest extends TestAbstract
{
    /**
     * @return void
     */
    public function testEncryptDecrypt()
    {
        $adapter = new NullAdapter();
        $encrypted = $adapter->encrypt('a', 'foo');
        $this->assertEquals('foo', $encrypted);
        $this->assertEquals('foo', $adapter->decrypt('a', $encrypted));
        $this->assertEquals('foo', $adapter->decrypt('a', 'foo'));
    }

    /**
     * @return void
     */
    public function testTypes()
    {
        $adapter = new NullAdapter();

        $date = Date::createYMDHISM(2023, 10, 10, 10, 10, 10);
        $this->assertEquals($date, $adapter->encrypt('a', $date));
        $this->assertEquals($date, $adapter->decrypt('a', $date));
    }
}
