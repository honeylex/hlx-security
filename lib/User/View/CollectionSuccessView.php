<?php

namespace Hlx\Security\User\View;

use Honeybee\Infrastructure\Template\TemplateRendererInterface;
use Silex\Application;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

class CollectionSuccessView
{
    protected $templateRenderer;

    protected $urlGenerator;

    public function __construct(
        TemplateRendererInterface $templateRenderer,
        UrlGeneratorInterface $urlGenerator
    ) {
        $this->templateRenderer = $templateRenderer;
        $this->urlGenerator = $urlGenerator;
    }

    public function renderHtml(Request $request, Application $app)
    {
        $users = $request->attributes->get('users');

        return $this->templateRenderer->render(
            '@hlx-security/user/collection.html.twig',
            [ 'q' => $request->query->get('q'), 'users' => $users ]
        );
    }

    public function renderJson(Request $request, Application $app)
    {
        return new JsonResponse(null, JsonResponse::HTTP_NOT_ACCEPTABLE);
    }
}
