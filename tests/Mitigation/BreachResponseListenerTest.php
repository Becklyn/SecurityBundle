<?php

namespace Tests\Becklyn\SecurityBundle\Tests\Mitigation\Breach;

use Becklyn\SecurityBundle\Html\HtmlNonceInjector;
use Becklyn\SecurityBundle\Mitigation\Breach\BreachResponseListener;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\HttpKernel\KernelInterface;

class BreachResponseListenerTest extends TestCase
{
    /**
     * Builds all services
     *
     * @param HtmlNonceInjector $nonceInjector
     * @param bool              $isMasterRequest
     * @param bool              $isSecure
     * @return array
     */
    private function buildServices (HtmlNonceInjector $nonceInjector, bool $isMasterRequest, bool $isSecure) : array
    {
        $response = $this->createMock(Response::class);
        $request = $this->createMock(Request::class);

        $event = new ResponseEvent(
            $this->createMock(KernelInterface::class),
            $request,
            $isMasterRequest ? HttpKernelInterface::MASTER_REQUEST : HttpKernelInterface::SUB_REQUEST,
            $response
        );

        if ($isMasterRequest)
        {
            $request
                ->expects(self::once())
                ->method("isSecure")
                ->willReturn($isSecure);
        }

        return [
            new BreachResponseListener($nonceInjector),
            $event,
            $response
        ];
    }


    /**
     * @return array
     */
    public function dataProviderInvalidMasterSecurePermutations () : array
    {
        return [
            [true, false],
            [false, true],
            [false, false],
        ];
    }


    /**
     * Tests all invalid cases, where the listener shouldn't run
     *
     * @dataProvider dataProviderInvalidMasterSecurePermutations
     *
     * @param bool $isMasterRequest
     * @param bool $isSecure
     */
    public function testInvalidMasterSecurePermutations (bool $isMasterRequest, bool $isSecure) : void
    {
        $nonceInjector = $this->getMockBuilder(HtmlNonceInjector::class)
            ->disableOriginalConstructor()
            ->getMock();

        /**
         * @type BreachResponseListener $listener
         * @type \PHPUnit_Framework_MockObject_MockObject $event
         */
        [$listener, $event] = $this->buildServices($nonceInjector, $isMasterRequest, $isSecure);

        $nonceInjector
            ->expects(self::never())
            ->method("injectNonce");

        $listener->onResponse($event);
    }


    /**
     * Tests the correct interaction of the listener with the response + nonce injection
     */
    public function testEventRegistration ()
    {
        $nonceInjector = $this->getMockBuilder(HtmlNonceInjector::class)
            ->disableOriginalConstructor()
            ->getMock();

        /**
         * @type BreachResponseListener $listener
         * @type ResponseEvent $event
         * @type MockObject $response
         */
        [$listener, $event, $response] = $this->buildServices($nonceInjector, true, true);

        $rawHtml = '<html>content</html>';
        $injectedHtml = '<html>content<!-- injected --></html>';

        $nonceInjector
            ->expects(self::once())
            ->method("injectNonce")
            ->with($rawHtml)
            ->willReturn($injectedHtml);

        $response
            ->expects(self::once())
            ->method("getContent")
            ->willReturn($rawHtml);

        $response
            ->expects(self::once())
            ->method("setContent")
            ->with($injectedHtml);

        $listener->onResponse($event);
    }
}
