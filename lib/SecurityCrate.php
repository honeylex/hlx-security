<?php

namespace Hlx\Security;

use Honeybee\FrameworkBinding\Silex\Crate\Crate;
use Silex\Application;

class SecurityCrate extends Crate
{
    public function connect(Application $app)
    {
        $routing = $app['controllers_factory'];

        require $this->getConfigDir() . '/routing.php';

        return $routing;
    }
}