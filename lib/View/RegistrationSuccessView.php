<?php

namespace Hlx\Security\View;

use Honeybee\FrameworkBinding\Silex\Config\ConfigProviderInterface;
use Silex\Application;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

class RegistrationSuccessView
{
    protected $configProvider;

    protected $urlGenerator;

    public function __construct(
        ConfigProviderInterface $configProvider,
        UrlGeneratorInterface $urlGenerator
    ) {
        $this->configProvider = $configProvider;
        $this->urlGenerator = $urlGenerator;
    }

    public function renderHtml(Request $request, Application $app)
    {
        $targetPath = $this->configProvider->getSetting('hlx.security.auto_login.enabled') && $request->hasSession()
            ? $this->configProvider->getSetting('hlx.security.auto_login.target_path', 'home')
            : 'hlx.security.login';

        return $app->redirect($this->urlGenerator->generate($targetPath));
    }

    public function renderJson(Request $request, Application $app)
    {
        return new JsonResponse(null, JsonResponse::HTTP_NOT_ACCEPTABLE);
    }
}
