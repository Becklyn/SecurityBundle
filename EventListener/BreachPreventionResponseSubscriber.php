<?php

namespace Becklyn\SecurityBundle\EventListener;

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
class BreachPreventionResponseSubscriber implements EventSubscriberInterface
{
    public function onResponse (FilterResponseEvent $event)
    {
        if (!$event->isMasterRequest())
        {
            return;
        }

        $response = $event->getResponse();
        $content = $response->getContent();
    }


    private function injectNonce (Response $response)
    {
        $content = $response->getContent();
        $pos = \strripos($content, '</body>');

        if (false === $pos)
        {
            return;
        }

        $randomData = random_bytes(25);
        $nonce = substr(base64_encode($randomData), 0, random_int(1, 32));
        $nonceSnippet = "<!-- {$nonce} -->";

        $content = substr($content, 0, $pos) . $nonceSnippet . substr($content, $pos);
        $response->setContent($content);
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
