<?php

namespace Tests\Becklyn\SecurityBundle\Tests\Html;

use Becklyn\SecurityBundle\Html\HtmlNonceInjector;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;


class HtmlNonceInjectorTest extends TestCase
{
    public function testInjection () : void
    {
        $html = '<html><body><p>Test</p></body></html>';
        $injector = new HtmlNonceInjector(new NullLogger());

        $withInjection = $injector->injectNonce($html);
        self::assertStringMatchesFormat('<html><body><p>Test</p>%s</body></html>', $withInjection);
    }
}
