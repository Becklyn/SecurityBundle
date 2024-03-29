<?php declare(strict_types=1);

namespace Becklyn\SecurityBundle\Mitigation\Breach;

use Becklyn\SecurityBundle\Html\HtmlNonceInjector;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\BinaryFileResponse;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\StreamedResponse;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
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
    private HtmlNonceInjector $nonceInjector;


    public function __construct (HtmlNonceInjector $nonceInjector)
    {
        $this->nonceInjector = $nonceInjector;
    }


    public function onResponse (ResponseEvent $event) : void
    {
        if (!$event->isMainRequest() || !$event->getRequest()->isSecure())
        {
            return;
        }

        $response = $event->getResponse();

        switch (true)
        {
            // don't modify unsupported responses
            case $response instanceof BinaryFileResponse:
            case $response instanceof JsonResponse:
            case $response instanceof StreamedResponse:
            case $response instanceof RedirectResponse:
                return;

            default:
                $response->setContent(
                    $this->nonceInjector->injectNonce($response->getContent())
                );
                break;
        }
    }


    /**
     * @inheritdoc
     */
    public static function getSubscribedEvents () : array
    {
        return [
            KernelEvents::RESPONSE => "onResponse",
        ];
    }
}
