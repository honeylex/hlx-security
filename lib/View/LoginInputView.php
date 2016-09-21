<?php

namespace Hlx\Security\View;

use Honeybee\Infrastructure\Template\TemplateRendererInterface;
use Silex\Application;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;

class LoginInputView
{
    protected $templateRenderer;

    public function __construct(TemplateRendererInterface $templateRenderer)
    {
        $this->templateRenderer = $templateRenderer;
    }

    public function renderHtml(Request $request, Application $app)
    {
        $form = $request->attributes->get('form');
        $error = $app['security.last_error']($request);
        $lastUsername = $request->getSession()->get('_security.last_username');

        return $this->templateRenderer->render(
            '@hlx-security/login.html.twig',
            [
                'form' => $form->createView(),
                'last_username' => $lastUsername,
                'errors' => (array) $error
            ]
        );
    }

    public function renderJson(Request $request, Application $app)
    {
        return new JsonResponse(null, JsonResponse::HTTP_NOT_ACCEPTABLE);
    }
}
