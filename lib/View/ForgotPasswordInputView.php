<?php

namespace Hlx\Security\View;

use Honeylex\Renderer\TemplateRendererInterface;
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
        // @todo extract form validation errors for JSON response
        $errors = $request->attributes->get('errors');

        if ($errors) {
            $jsonResponse = new JsonResponse($errors, JsonResponse::HTTP_BAD_REQUEST);
        } else {
            $jsonResponse = new JsonResponse(null, JsonResponse::HTTP_NOT_ACCEPTABLE);
        }

        return $jsonResponse;
    }
}
