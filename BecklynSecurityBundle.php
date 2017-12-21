<?php

namespace Becklyn\SecurityBundle;

use Becklyn\SecurityBundle\DependencyInjection\BecklynSecurityExtension;
use Symfony\Component\HttpKernel\Bundle\Bundle;


class BecklynSecurityBundle extends Bundle
{
    /**
     * @inheritdoc
     */
    public function getContainerExtension ()
    {
        return new BecklynSecurityExtension();
    }
}
