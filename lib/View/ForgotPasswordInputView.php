<?php

namespace Hlx\Security\View;

use Honeybee\Infrastructure\Template\TemplateRendererInterface;
use Silex\Application;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;

class ForgotPasswordInputView
{
    protected $templateRenderer;

    public function __construct(TemplateRendererInterface $templateRenderer)
    {
        $this->templateRenderer = $templateRenderer;
    }

    public function renderHtml(Request $request, Application $app)
    {
        $form = $request->attributes->get('form');
        $errors = $request->attributes->get('errors');

        return $this->templateRenderer->render(
            '@hlx-security/forgot_password.html.twig',
            [ 'form' => $form->createView(), 'errors' => $errors ]
        );
    }

    public function renderJson(Request $request, Application $app)
    {
        return new JsonResponse(null, JsonResponse::HTTP_NOT_ACCEPTABLE);
    }
}
