<?php

namespace Becklyn\SecurityBundle\Mitigation\Breach;

use Psr\Log\LoggerInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\FilterResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;


/**
 * Tries to mitigate the BREACH SSL + deflate attack.
 *
 * HTTPS is vulnerable against a length guessing attack,
 * if there is user-directed content in a web page with HTTPS + gzip.
 *
 * As it is no option to deactivate either one of them, the response is padded with random content.
 */
class BreachResponseListener implements EventSubscriberInterface
{
    /**
     * @var HtmlNonceInjector
     */
    private $nonceInjector;


    /**
     * @param HtmlNonceInjector $nonceInjector
     */
    public function __construct (HtmlNonceInjector $nonceInjector)
    {
        $this->nonceInjector = $nonceInjector;
    }


    /**
     * @param FilterResponseEvent $event
     */
    public function onResponse (FilterResponseEvent $event)
    {
        if (!$event->isMasterRequest() || !$event->getRequest()->isSecure())
        {
            return;
        }

        $response = $event->getResponse();
        $response->setContent(
            $this->nonceInjector->injectNonce($response->getContent())
        );
    }


    /**
     * @inheritdoc
     */
    public static function getSubscribedEvents ()
    {
        return [
            KernelEvents::RESPONSE => "onResponse",
        ];
    }
}
