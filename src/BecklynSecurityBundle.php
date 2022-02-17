<?php declare(strict_types=1);

namespace Becklyn\SecurityBundle;

use Becklyn\SecurityBundle\DependencyInjection\BecklynSecurityExtension;
use Symfony\Component\DependencyInjection\Extension\ExtensionInterface;
use Symfony\Component\HttpKernel\Bundle\Bundle;

class BecklynSecurityBundle extends Bundle
{
    /**
     * @inheritdoc
     */
    public function getContainerExtension () : ?ExtensionInterface
    {
        return new BecklynSecurityExtension();
    }
}
