<?php

namespace Hlx\Security\User\View\Task;

use Silex\Application;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

class CreateSuccessView
{
    protected $urlGenerator;

    public function __construct(UrlGeneratorInterface $urlGenerator)
    {
        $this->urlGenerator = $urlGenerator;
    }

    public function renderHtml(Request $request, Application $app)
    {
        return $app->redirect($this->urlGenerator->generate('hlx.security.user.list'));
    }

    public function renderJson(Request $request, Application $app)
    {
        return new JsonResponse(null, JsonResponse::HTTP_NOT_ACCEPTABLE);
    }
}
