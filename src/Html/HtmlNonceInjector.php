<?php declare(strict_types=1);

namespace Becklyn\SecurityBundle\Html;

use Psr\Log\LoggerInterface;

class HtmlNonceInjector
{
    private LoggerInterface $logger;


    public function __construct (LoggerInterface $logger)
    {
        $this->logger = $logger;
    }


    /**
     * Injects a nonce in the HTML, if it is a full HTML response (i.e. if there is a closing body tag).
     */
    public function injectNonce (string $html) : string
    {
        try
        {
            $pos = \strripos($html, '</body>');

            if (false === $pos)
            {
                return $html;
            }

            $randomData = \random_bytes(25);
            $nonce = \substr(\base64_encode($randomData), 0, \random_int(1, 32));
            $nonceSnippet = "<!-- {$nonce} -->";

            return \substr($html, 0, $pos) . $nonceSnippet . \substr($html, $pos);
        }
        catch (\Exception $e)
        {
            $this->logger->error("Could not inject nonce as random data generation failed.", [
                "innerException" => $e,
            ]);

            return $html;
        }
    }
}
